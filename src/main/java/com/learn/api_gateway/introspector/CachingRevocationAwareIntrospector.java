package com.learn.api_gateway.introspector;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringReactiveOpaqueTokenIntrospector;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.learn.api_gateway.config.SecurityConfig;
import com.learn.api_gateway.config.properties.OpaqueTokenProperties;
import com.learn.api_gateway.config.properties.SecurityCacheProperties;
import com.learn.api_gateway.service.TokenRevocationService;
import com.learn.api_gateway.util.TokenUtils;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Slf4j
public class CachingRevocationAwareIntrospector implements ReactiveOpaqueTokenIntrospector {
	private final ReactiveOpaqueTokenIntrospector delegate;
    private final ReactiveRedisTemplate<String, byte[]> principalCache;
    private final TokenRevocationService tokenRevocationService;
    private final SecurityCacheProperties cacheProps;
    private final OpaqueTokenProperties opaqueProps;
    private final ObjectMapper objectMapper;
    private final Duration clockSkew = SecurityConfig.CLOCK_SKEW;

    private boolean jwsValidationEnabled = false;
    private boolean keyRotationAwarenessEnabled = false;
    
    private static final Duration KEY_ROTATION_CHECK_INTERVAL = Duration.ofMinutes(5);
    private static volatile Instant lastRotationCheck = Instant.EPOCH;

    // Cache last known secret/public key fingerprint
    private volatile String lastKeyFingerprint;
    
    private URL jwksUri;
    private final AtomicReference<JWKSet> cachedJwkSet = new AtomicReference<>();
    private volatile Instant lastJwksFetch = Instant.EPOCH;
    private final Duration jwksRefreshInterval = Duration.ofMinutes(10);

    public CachingRevocationAwareIntrospector(String introspectionUri,
                                              String clientId,
                                              String clientSecret,
                                              ReactiveRedisTemplate<String, byte[]> principalCache,
                                              TokenRevocationService tokenRevocationService,
                                              SecurityCacheProperties cacheProps,
                                              OpaqueTokenProperties opaqueProps,
                                              ObjectMapper objectMapper) {
        this.delegate = SpringReactiveOpaqueTokenIntrospector
                .withIntrospectionUri(introspectionUri)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build();
        this.principalCache = principalCache;
        this.tokenRevocationService = tokenRevocationService;
        this.cacheProps = cacheProps;
        this.opaqueProps = opaqueProps;
        this.objectMapper = objectMapper;
    }

    // === Config toggles ===
    public void enableJwsSignatureValidation(boolean enabled) {
        this.jwsValidationEnabled = enabled;
        log.info("JWS signature validation {}", enabled ? "enabled" : "disabled");
    }

    public void enableKeyRotationAwareness(boolean enabled) {
        this.keyRotationAwarenessEnabled = enabled;
        log.info("Key rotation awareness {}", enabled ? "enabled" : "disabled");
    }
    
    public void setJwksUri(String jwksUri) {
        try {
            this.jwksUri = new URL(jwksUri);
            log.info("Configured JWKS URI: {}", jwksUri);
        } catch (Exception e) {
            log.warn("Invalid JWKS URI: {}", jwksUri, e);
        }
    }

    @Override
    public Mono<OAuth2AuthenticatedPrincipal> introspect(String token) {
        if (jwsValidationEnabled && isLikelyJwt(token)) {
            try {
                validateJwsSignature(token);
            } catch (Exception e) {
                log.warn("JWS signature validation failed: {}", e.getMessage());
                return Mono.error(new OAuth2AuthenticationException(
                        new OAuth2Error("invalid_token", "Invalid JWS signature", null), e));
            }
        }

        if (keyRotationAwarenessEnabled) {
            detectKeyRotationIfAny();
        }

        String cacheKey = "introspect:" + DigestUtils.sha256Hex(token);

        return tokenRevocationService.isTokenRevoked(token, null)
                .flatMap(isRevoked -> {
                    if (Boolean.TRUE.equals(isRevoked)) {
                        return tokenRevocationService.cacheInvalidToken(token)
                                .then(Mono.error(new OAuth2AuthenticationException(
                                        new OAuth2Error("invalid_token", "Token revoked", null))));
                    }

                    return principalCache.opsForValue().get(cacheKey)
                            .flatMap(bytes -> Mono.defer(() -> {
                                try {
                                    Map<String, Object> cached = decompressToMap(bytes);
                                    OAuth2AuthenticatedPrincipal principal = buildPrincipalWithRoles(cached);
                                    return tokenRevocationService.isTokenRevoked(token, null)
                                            .flatMap(revoked -> {
                                                if (Boolean.TRUE.equals(revoked)) {
                                                    return tokenRevocationService.cacheInvalidToken(token)
                                                            .then(Mono.error(new OAuth2AuthenticationException(
                                                                    new OAuth2Error("invalid_token", "Token revoked", null))));
                                                }
                                                return Mono.just(principal);
                                            });
                                } catch (Exception e) {
                                    log.warn("Corrupt cached principal for key={}, evicting", cacheKey, e);
                                    return principalCache.delete(cacheKey).then(Mono.empty());
                                }
                            }))
                            .switchIfEmpty(delegate.introspect(token)
                                    .flatMap(principal -> handleDelegateResult(token, cacheKey, principal))
                                    .onErrorResume(OAuth2AuthenticationException.class, ex ->
                                            tokenRevocationService.cacheInvalidToken(token).then(Mono.error(ex)))
                                    .onErrorResume(Throwable.class, ex -> {
                                        log.error("Unexpected error introspecting token", ex);
                                        return tokenRevocationService.cacheInvalidToken(token)
                                                .then(Mono.error(new OAuth2AuthenticationException(
                                                        new OAuth2Error("invalid_token", "introspection error", null), ex)));
                                    })
                            );
                });
    }
    
    private void detectKeyRotationIfAny() {
    	try {
            // --- Throttle key rotation check ---
            Instant now = Instant.now();
            if (Duration.between(lastRotationCheck, now).compareTo(KEY_ROTATION_CHECK_INTERVAL) < 0) {
                return; // skip if checked recently
            }
            lastRotationCheck = now;

            String fingerprint = null;
            if (opaqueProps.getOauth2().getOpaqueToken().getClientSecret() != null) {
                fingerprint = DigestUtils.sha256Hex(opaqueProps.getOauth2().getOpaqueToken().getClientSecret());
            } else if (opaqueProps.getOauth2().getResourceserver().getJwkPublicKey()!= null) {
                fingerprint = DigestUtils.sha256Hex(opaqueProps.getOauth2().getResourceserver().getJwkPublicKey());
            }

            if (fingerprint != null && lastKeyFingerprint != null && !lastKeyFingerprint.equals(fingerprint)) {
                log.info("Key rotation detected — scheduling cache eviction for principals (non-blocking).");

                // Safe reactive delete with error handling & bounded scheduling
                principalCache.keys("introspect:*")
                        .flatMap(principalCache::delete)
                        .doOnError(e -> log.warn("Key rotation cleanup failed", e))
                        .doOnComplete(() -> log.info("Principal cache cleared after key rotation"))
                        .subscribeOn(Schedulers.boundedElastic()) // offload from event loop
                        .subscribe(); // fire & forget (with safety hooks)
            }
            lastKeyFingerprint = fingerprint;
        } catch (Exception e) {
            log.warn("Failed to detect or handle key rotation", e);
        }
    }

    private boolean isLikelyJwt(String token) {
        return token != null && token.split("\\.").length == 3;
    }
    
    private void validateJwsSignature(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            JWSHeader header = jwt.getHeader();
            String alg = header.getAlgorithm().getName();

            boolean verified = false;

            if (alg.startsWith("HS")) {
                Mac mac = Mac.getInstance(switch (alg) {
                    case "HS512" -> "HmacSHA512";
                    case "HS384" -> "HmacSHA384";
                    default -> "HmacSHA256";
                });
                mac.init(new SecretKeySpec(
                		opaqueProps.getOauth2().getOpaqueToken().getClientSecret().getBytes(StandardCharsets.UTF_8),
                        mac.getAlgorithm()
                ));

                byte[] expectedSig = mac.doFinal(jwt.getSigningInput()); // <-- fixed
                verified = MessageDigest.isEqual(expectedSig, jwt.getSignature().decode());

            } else if (alg.startsWith("RS")) {
            	RSAPublicKey publicKey = fetchPublicKeyFromJwks(header.getKeyID());
                if (publicKey == null) {
                    log.debug("No JWKS match for kid={}, falling back to static key", header.getKeyID());
                    publicKey = opaqueProps.publicKey(); // fallback static public key
                }
                if (publicKey != null) {
                    JWSVerifier verifier = new RSASSAVerifier(publicKey);
                    verified = jwt.verify(verifier);
                } else {
                    log.warn("No valid RSA public key available for validation");
                }
            }

            if (!verified) {
                throw new SecurityException("Invalid JWS signature for algorithm: " + alg);
            }

        } catch (Exception e) {
        	throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_token"),
                    "Signature validation failed: " + e.getMessage(),
                    e
            );
        }
    }
    
    private RSAPublicKey fetchPublicKeyFromJwks(String kid) {
        if (jwksUri == null) {
            return null;
        }
        try {
            Instant now = Instant.now();
            if (cachedJwkSet.get() == null ||
                Duration.between(lastJwksFetch, now).compareTo(jwksRefreshInterval) > 0) {
                log.debug("Refreshing JWKS from {}", jwksUri);
                JWKSet jwkSet = JWKSet.load(jwksUri);
                cachedJwkSet.set(jwkSet);
                lastJwksFetch = now;
            }

            JWKSet jwkSet = cachedJwkSet.get();
            if (jwkSet == null) return null;

            JWK jwk = jwkSet.getKeyByKeyId(kid);
            if (jwk instanceof RSAKey rsaKey) {
                RSAPublicKey publicKey = rsaKey.toRSAPublicKey();
                log.debug("Resolved RSA public key for kid={}", kid);
                return publicKey;
            }

            log.debug("No RSA JWK found for kid={}", kid);

        } catch (Exception e) {
            log.warn("Failed to fetch or parse JWKS from {}", jwksUri, e);
        }
        return null;
    }

    private Mono<OAuth2AuthenticatedPrincipal> handleDelegateResult(String token, String cacheKey,
                                                                    OAuth2AuthenticatedPrincipal principal) {
        Object active = principal.getAttribute("active");
        if (!(Boolean.TRUE.equals(active) || "true".equalsIgnoreCase(String.valueOf(active)))) {
            return tokenRevocationService.cacheInvalidToken(token)
                    .then(Mono.error(new OAuth2AuthenticationException(
                            new OAuth2Error("invalid_token", "inactive token", null))));
        }

        return Mono.defer(() -> {
            try {
                OAuth2AuthenticatedPrincipal validated = validatePrincipal(principal);
                String userId = validated.getAttribute("sub");

                return tokenRevocationService.isTokenRevoked(token, userId)
                        .flatMap(revoked -> {
                            if (Boolean.TRUE.equals(revoked)) {
                                return tokenRevocationService.cacheInvalidToken(token)
                                        .then(Mono.error(new OAuth2AuthenticationException(
                                                new OAuth2Error("invalid_token", "revoked token", null))));
                            }

                            // Cache minimal claims
                            Map<String, Object> minimal = extractEssentialClaims(validated);
                            Duration ttl = TokenUtils.ttlFromExp(minimal,
                                    Duration.ofMinutes(cacheProps.getSafeTtlMinutes()), clockSkew);

                            if (!ttl.isZero() && !ttl.isNegative()) {
                            	return Mono.fromCallable(() -> compressMap(minimal))
                            		    .flatMap(compressed -> {
                            		        Duration effectiveTtl = ttl != null && !ttl.isZero() && !ttl.isNegative()
                            		                ? ttl
                            		                : Duration.ofMinutes(cacheProps.getSafeTtlMinutes());

                            		        return principalCache.opsForValue()
                            		                .set(cacheKey, compressed, effectiveTtl)
                            		                .doOnSuccess(ok -> log.debug("Cached principal key={} ttl={}s size={}B",
                            		                        cacheKey, effectiveTtl.toSeconds(), compressed.length))
                            		                .thenReturn(validated);
                            		    })
                            		    .onErrorResume(IOException.class, e -> {
                            		        log.error("Failed to compress cache entry", e);
                            		        return Mono.just(validated);
                            		    });
                            }
                            return Mono.just(validated);
                        });

            } catch (OAuth2AuthenticationException e) {
                return tokenRevocationService.cacheInvalidToken(token).then(Mono.error(e));
            } catch (Exception e) {
                log.error("Error validating principal from introspection", e);
                return tokenRevocationService.cacheInvalidToken(token)
                        .then(Mono.error(new OAuth2AuthenticationException(
                                new OAuth2Error("invalid_token", "introspection validation error", null), e)));
            }
        });
    }

    /** Keep only lightweight essential attributes for caching. */
    private Map<String, Object> extractEssentialClaims(OAuth2AuthenticatedPrincipal principal) {
        Map<String, Object> attrs = principal.getAttributes();
        Map<String, Object> map = new HashMap<>();
        map.put("sub", attrs.get("sub"));
        map.put("name", attrs.getOrDefault("name", attrs.get("preferred_username")));
        map.put("exp", attrs.get("exp"));
        map.put("realm_access", attrs.get("realm_access"));
        map.put("resource_access", attrs.get("resource_access"));
        map.put("_name", principal.getName());
        return map;
    }
    
    private byte[] compressMap(Map<String, Object> map) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
            gzip.write(objectMapper.writeValueAsBytes(map));
        }
        return baos.toByteArray();
    }

    private Map<String, Object> decompressToMap(byte[] bytes) throws IOException {
        try (GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(bytes))) {
            return objectMapper.readValue(gis, new TypeReference<>() {});
        }
    }

    // --- helpers ---
    private OAuth2AuthenticatedPrincipal validatePrincipal(org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal principal) {
        // --- issued-at (iat) sanity check: reject tokens that claim issuance in the future ---
    	Object iatObj = principal.getAttribute("iat");
        if (iatObj != null) {
            Long iatEpoch = null;

            try {
                if (iatObj instanceof Number n) {
                    // e.g. Long, Integer, Double
                    iatEpoch = n.longValue();
                } else if (iatObj instanceof String s) {
                    String trimmed = s.trim();

                    if (trimmed.matches("\\d+")) {
                        // purely numeric string -> epoch seconds
                        iatEpoch = Long.parseLong(trimmed);
                    } else {
                        // try ISO-8601 style timestamp
                        try {
                            Instant parsed = Instant.parse(trimmed);
                            iatEpoch = parsed.getEpochSecond();
                        } catch (DateTimeParseException e) {
                            log.warn("Skipping iat validation: unsupported string format iat='{}' (type={})",
                                    trimmed, iatObj.getClass().getName());
                        }
                    }
                } else {
                    log.warn("Skipping iat validation: unsupported type {} value={}",
                            iatObj.getClass().getName(), iatObj);
                }

                if (iatEpoch != null) {
                    long now = Instant.now().getEpochSecond();
                    if (iatEpoch - clockSkew.getSeconds() > now) {
                        throw new OAuth2IntrospectionException("Token issued in the future (iat): " + iatEpoch);
                    }
                }

            } catch (NumberFormatException e) {
                // Do NOT fail the whole token, just log and continue
                log.warn("Skipping iat validation due to invalid numeric format: {}", iatObj);
            }
        }

        // --- issuer validation ---
        String expectedIssuer = opaqueProps.getExpectedIssuer();
        if (expectedIssuer != null) {
            String iss = principal.getAttribute("iss");
            if (iss == null || !iss.replaceAll("/$", "").equals(expectedIssuer.replaceAll("/$", ""))) {
                log.warn("Rejecting token due to invalid issuer: {}", iss);
                throw new OAuth2IntrospectionException("Invalid token issuer");
            }
        }

        // audience check
        String expectedAudience = opaqueProps.getOauth2().getOpaqueToken().getExpectedAudience();
        if (expectedAudience != null) {
            Object audAttr = principal.getAttribute("aud");
            boolean validAud = false;
            if (audAttr instanceof String s) {
                validAud = expectedAudience.equals(s);
            } else if (audAttr instanceof Collection<?> c) {
                validAud = c.contains(expectedAudience);
            }
            if (!validAud) {
                log.warn("Rejecting token due to invalid audience: {}", audAttr);
                throw new OAuth2IntrospectionException("Invalid token audience");
            }
        }

        // build roles -> authorities (same as before)
        Map<String, Object> attrs = principal.getAttributes();
        String name = Objects.toString(attrs.getOrDefault("name", attrs.getOrDefault("sub", "anonymous")));
        Set<String> roles = new HashSet<>();

        Object realmAccess = attrs.get("realm_access");
        if (realmAccess instanceof Map<?, ?> m && m.get("roles") instanceof Collection<?> rc) {
            rc.forEach(r -> roles.add(String.valueOf(r)));
        }
        Object resAccess = attrs.get("resource_access");
        if (resAccess instanceof Map<?, ?> ra) {
            ra.values().forEach(v -> {
                if (v instanceof Map<?, ?> mm && mm.get("roles") instanceof Collection<?> c) {
                    c.forEach(r -> roles.add(String.valueOf(r)));
                }
            });
        }

        List<GrantedAuthority> authorities = roles.stream()
        		.filter(Objects::nonNull)
                .map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role.toUpperCase(Locale.ROOT))
                .filter(role -> opaqueProps.getNormalizedTrustedRoles().isEmpty()
                        || opaqueProps.getNormalizedTrustedRoles().contains(role))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        if (authorities.isEmpty() && !opaqueProps.getNormalizedTrustedRoles().isEmpty()) {
            throw new OAuth2IntrospectionException("No trusted roles present in token");
        }

        return new org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal(name, attrs, authorities);
    }

    private OAuth2AuthenticatedPrincipal buildPrincipalWithRoles(Map<String, Object> cachedAttrs) {
        String name = Objects.toString(cachedAttrs.getOrDefault("_name", cachedAttrs.get("sub")));

        // restore roles from cached attributes (if you stored them)
        Collection<GrantedAuthority> authorities = extractAuthorities(cachedAttrs);

        return new DefaultOAuth2AuthenticatedPrincipal(
                name,
                cachedAttrs,
                authorities
        );
    }

    @SuppressWarnings("unchecked")
    private Collection<GrantedAuthority> extractAuthorities(Map<String, Object> attrs) {
        List<String> roles = new ArrayList<>();

        // Handle Keycloak realm_access roles
        Map<String, Object> realmAccess = (Map<String, Object>) attrs.get("realm_access");
        if (realmAccess != null && realmAccess.get("roles") instanceof Collection) {
            roles.addAll(((Collection<String>) realmAccess.get("roles")));
        }

        // Handle Keycloak resource_access roles
        Map<String, Object> resourceAccess = (Map<String, Object>) attrs.get("resource_access");
        if (resourceAccess != null) {
            for (Object clientEntry : resourceAccess.values()) {
                if (clientEntry instanceof Map) {
                    Object r = ((Map<?, ?>) clientEntry).get("roles");
                    if (r instanceof Collection) {
                        roles.addAll((Collection<String>) r);
                    }
                }
            }
        }

        return roles.stream()
                .filter(Objects::nonNull)
                .map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role.toUpperCase())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    }
    
    public String getCacheKeyPattern() {
        return "introspect:";
    }
}
