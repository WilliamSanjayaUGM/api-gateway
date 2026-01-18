package com.learn.api_gateway.filter;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.learn.api_gateway.config.SecurityConfig;
import com.learn.api_gateway.config.properties.OpaqueTokenProperties;
import com.learn.api_gateway.config.properties.RecaptchaConfigProperties;
import com.learn.api_gateway.service.AuditService;
import com.learn.api_gateway.util.ErrorResponseWriter;
import com.learn.api_gateway.util.TraceConstants;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

// TODO: show a dynamic approach where TRUSTED_ROLES comes from Keycloak roles config, so you don’t have to hardcode them in Java. This is better for large, multi-realm setups.
@Slf4j
@Component
@Order(-99) // After AUTHENTICATION (-100)
public class OpaqueTokenClaimPropagatingFilter implements WebFilter{
	
	private final OpaqueTokenProperties props;
	private final RecaptchaConfigProperties recaptchaProps;
    private final WebClient keycloakClient;
    private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
    private final AuditService auditService;
    private final ErrorResponseWriter errorResponseWriter;

    private static final int MAX_ROLE_HEADER_LENGTH = 2048;
    private static final int MAX_TOTAL_ROLE_HEADER_SIZE = 8192;
    private static final int MAX_JWT_SIZE = 10 * 1024; // 10 KB
    private static final String TOKEN_REPLAY_PREFIX = "replay:";
    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    // Default public patterns (can be overridden by props.getExcludedPaths())
    private static final List<String> DEFAULT_PUBLIC_PATH_PATTERNS = List.of(
    		"/auth/signup",
    	    "/auth/refresh",
    	    "/auth/forgot-password",
    	    "/auth/step-up",
    	    "/auth/step-up/callback",
    	    "/actuator/**",
    	    "/public/**",
    	    "/health",
    	    "/favicon.ico",
    	    "/v1/auth/signup",
    	    "/v1/auth/step-up",
    	    "/v1/auth/step-up/callback",
    	    "/oauth-proxy/**",
    	    "/realms/*/protocol/openid-connect/**"
//    	    ,"/v1/product/test",
//    	    "/product-detail/test"
    );

    // Local caches
    private final Cache<String, List<String>> sanitizedRolesCache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofMinutes(1))
            .maximumSize(20_000)
            .build();

    private final Cache<String, Instant> tokenExpiryCache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofMinutes(10))
            .maximumSize(50_000)
            .build();

    public OpaqueTokenClaimPropagatingFilter(
            OpaqueTokenProperties props,
            @Qualifier("keycloakWebClient") WebClient keycloakClient,
            ReactiveRedisTemplate<String, String> reactiveRedisTemplate,
            AuditService auditService,
            RecaptchaConfigProperties recaptchaProps,
            ErrorResponseWriter errorResponseWriter) {
        this.props = props;
        this.recaptchaProps=recaptchaProps;
        this.keycloakClient = keycloakClient;
        this.reactiveRedisTemplate = reactiveRedisTemplate;
        this.auditService = auditService;
        this.errorResponseWriter = errorResponseWriter;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain){
    	if (exchange.getResponse().isCommitted()) {
    	    log.debug("Response already committed, skipping OpaqueTokenClaimPropagatingFilter");
    	    return chain.filter(exchange);
    	}
        // Trace id
        String traceId = Optional.ofNullable(exchange.getAttribute(TraceConstants.TRACE_ID_CONTEXT_KEY))
                .map(Object::toString)
                .orElse(UUID.randomUUID().toString());
        exchange.getAttributes().put(TraceConstants.TRACE_ID_CONTEXT_KEY, traceId);

        String path = exchange.getRequest().getURI().getPath();
        log.info("------OpaqueTokenClaimPropagatingFilter is run with path: {}, traceId: {}", path,traceId);
        
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        if (route != null) {
            Object authMode = route.getMetadata().get("internal-auth");
            if ("required".equals(authMode)) {
                log.debug("Skipping OpaqueTokenClaimPropagatingFilter for internal-auth route={}",
                        route.getId());
                return chain.filter(exchange);
            }
        }
        
        // Build effective public patterns (from props if available), fallback to defaults
        List<String> publicPatterns = new ArrayList<>(DEFAULT_PUBLIC_PATH_PATTERNS);

        if (props.getExcludedPaths() != null && !props.getExcludedPaths().isEmpty()) {
            publicPatterns.addAll(props.getExcludedPaths());
        }

        // If request path matches any public pattern -> bypass the filter completely
        for (String pattern : publicPatterns) {
            if (PATH_MATCHER.match(pattern, path)) {
                log.info("[traceId={}] Bypassing OpaqueTokenClaimPropagatingFilter for public path pattern={} path={}",
                        traceId, pattern, path);
                return chain.filter(exchange);
            }
        }

        // Check header oversize early (only if Authorization present)
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // Protected route but no bearer -> reject
            log.warn("[traceId={}] Missing Authorization Bearer for protected path {}", traceId, path);
//            return errorResponseWriter.write(exchange, HttpStatus.UNAUTHORIZED,
//                    "Missing or invalid Authorization Bearer token");
            return chain.filter(exchange);
        }

        String token = authHeader.substring(7);
        if (token.length() > MAX_JWT_SIZE) {
            log.warn("[traceId={}] Rejected oversized JWT: {} bytes (> {} bytes)", traceId, token.length(), MAX_JWT_SIZE);
            
            auditService.auditWarn(
                    "JWT_OVERSIZE",
                    "unknown",
                    (String) exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP),
                    path,
                    "JWT exceeds max size",
                    Map.of("size", token.length())
                );
            
//            return errorResponseWriter.write(exchange, HttpStatus.BAD_REQUEST,
//                  "JWT exceeds allowed size of " + MAX_JWT_SIZE + " bytes");

                return chain.filter(exchange);
        };
        // Principal may be resolved by upstream security WebFilter; require it for protected routes
//        return ReactiveSecurityContextHolder.getContext()
//                .map(SecurityContext::getAuthentication)
//                .filter(auth -> auth instanceof AbstractOAuth2TokenAuthenticationToken
//                		|| auth instanceof JwtAuthenticationToken)
//                .cast(AbstractOAuth2TokenAuthenticationToken.class)
//                .flatMap(auth -> handleAuth(exchange, chain, auth, traceId))
//                .switchIfEmpty(Mono.defer(() -> {
//                    // No principal despite having Bearer header — treat as unauthorized
//                    log.warn("[traceId={}] No authenticated principal found for protected request {}",
//                            traceId, path);
//                    return errorResponseWriter.write(exchange, HttpStatus.UNAUTHORIZED,
//                            "Invalid or unauthenticated token");
//                }))
//                .contextWrite(ctx -> ctx.put(TraceConstants.TRACE_ID_CONTEXT_KEY, traceId));
        
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .flatMap(auth -> {

                    if (auth instanceof AbstractOAuth2TokenAuthenticationToken<?> tokenAuth) {
                        return handleAuth(exchange, chain, tokenAuth, traceId);
                    }

                    log.warn("[traceId={}] Unsupported Authentication type: {}",
                            traceId, auth.getClass().getName());

//                    return errorResponseWriter.write(exchange, HttpStatus.UNAUTHORIZED,
//                            "Unsupported authentication type");
                    return chain.filter(exchange);
                })
//                .switchIfEmpty(Mono.defer(() -> {
//                    log.warn("[traceId={}] No authenticated principal found for protected request {}",
//                            traceId, path);
//                    return errorResponseWriter.write(exchange, HttpStatus.UNAUTHORIZED,
//                            "Invalid or unauthenticated token");
//                }))
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("[traceId={}] No authenticated principal found, skipping propagation for path={}",
                            traceId, path);
                    return chain.filter(exchange);
                }))
                .contextWrite(ctx -> ctx.put(TraceConstants.TRACE_ID_CONTEXT_KEY, traceId));
    }

    private Mono<Void> handleAuth(ServerWebExchange exchange,
                                  WebFilterChain chain,
                                  AbstractOAuth2TokenAuthenticationToken<?> auth,
                                  String traceId) {

    	Object principalObj = auth.getPrincipal();

        final Map<String, Object> attributes;
        final String userId;

        if (principalObj instanceof OAuth2AuthenticatedPrincipal oauthPrincipal) {
            // OPAQUE PATH (legacy)
            attributes = oauthPrincipal.getAttributes();
            userId = oauthPrincipal.getName();

        } else if (principalObj instanceof Jwt jwt) {
            // JWT PATH (Keycloak v26+)
            attributes = jwt.getClaims();
            userId = jwt.getSubject();

        } else {
            log.warn("[traceId={}] Unsupported principal type: {}",
                    traceId, principalObj.getClass().getName());
//            return errorResponseWriter.write(exchange, HttpStatus.UNAUTHORIZED,
//                    "Unsupported authentication principal");
            return chain.filter(exchange);
        }

        String tokenValue = auth.getToken().getTokenValue();

        String jti = Optional.ofNullable((String) attributes.get("jti"))
                .orElse(hashTokenPrefix(tokenValue));

        final Duration ttl;

        try {
            ttl = resolveTtlFromAttributes(attributes);
        } catch (IllegalStateException e) {
        	String msg = e.getMessage();
            if (msg != null && msg.startsWith("Missing exp")) {
                log.warn("[traceId={}] Token missing exp claim for user {}", traceId, maskUserId(userId));
//                return errorResponseWriter.write(exchange, HttpStatus.UNAUTHORIZED, "Invalid token (missing exp)");
                return chain.filter(exchange);
            }

            log.warn("[traceId={}] Expired token detected for user {}", traceId, maskUserId(userId));
//            return errorResponseWriter.write(exchange, HttpStatus.UNAUTHORIZED, "Expired token");
            return chain.filter(exchange);
        }

        // REPLAY PROTECTION (UNCHANGED)
        String redisKey = TOKEN_REPLAY_PREFIX + jti;

        return reactiveRedisTemplate.opsForValue()
                .setIfAbsent(redisKey, "1", ttl)
                .onErrorResume(ex -> {
                    boolean failClosed = Optional.ofNullable(recaptchaProps.isFailClosedOnRedisError()).orElse(true);
                    log.warn("[traceId={}] Redis setIfAbsent failed: {}, failClosed={}", traceId, ex.toString(), failClosed);
                    return Mono.just(!failClosed);
                })
                .flatMap(success -> {
                    if (!Boolean.TRUE.equals(success)) {
                        auditService.auditWarn(
                                "REPLAY_DETECTED",
                                userId,
                                (String) exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP),
                                exchange.getRequest().getPath().value(),
                                "Replay detected",
                                Map.of("jti", jti)
                        );
                        log.warn("[traceId={}] Replay detected for jti={}", traceId, jti);
//                        return errorResponseWriter.write(exchange, HttpStatus.FORBIDDEN,
//                                "Replay detected: token already used");
                        return chain.filter(exchange);
                    }

                    tokenExpiryCache.put(jti, Instant.now().plus(ttl));

                    return computeSanitizedRolesFromAttributes(attributes)
                            .flatMap(sanitizedRoles -> {
                                if (sanitizedRoles.isEmpty()) {
                                    auditService.auditWarn(
                                            "NO_TRUSTED_ROLES",
                                            userId,
                                            (String) exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP),
                                            exchange.getRequest().getPath().value(),
                                            "No trusted roles present",
                                            Map.of("trustedRoles", props.getNormalizedTrustedRoles())
                                    );
                                    
                                    log.warn("[traceId={}] No trusted roles for user={}",
                                            traceId, maskUserId(userId));
//                                    return errorResponseWriter.write(exchange, HttpStatus.FORBIDDEN,
//                                          "Insufficient roles");
                                    // DO NOT BLOCK
                                    return chain.filter(exchange);
                                }

                                return propagateRoles(
                                        exchange,
                                        chain,
                                        userId,
                                        jti,
                                        (String) exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP),
                                        traceId,
                                        sanitizedRoles
                                );
                            });
                });
    }
    
    private Duration resolveTtlFromAttributes(Map<String, Object> attributes) {

    	Object expAttr = attributes.get("exp");

        if (expAttr == null) {
            throw new IllegalStateException("Missing exp claim (null)");
        }

        final Instant exp;

        if (expAttr instanceof Instant instant) {
            // Spring Security often stores exp like this
            exp = instant;

        } else if (expAttr instanceof Number n) {
            // Standard JWT numeric date (seconds since epoch)
            exp = Instant.ofEpochSecond(n.longValue());

        } else if (expAttr instanceof String s) {
            String trimmed = s.trim();
            if (trimmed.matches("\\d+")) {
                // Numeric string case: "1764882420"
                exp = Instant.ofEpochSecond(Long.parseLong(trimmed));
            } else {
                // ISO-8601 string: "2025-12-05T03:52:20Z"
                exp = Instant.parse(trimmed);
            }

        } else {
            throw new IllegalStateException(
                "Missing exp claim (unsupported type: " + expAttr.getClass().getName() + ")"
            );
        }

        Duration ttl = Duration.between(Instant.now(), exp)
                .minus(SecurityConfig.CLOCK_SKEW);

        if (ttl.isNegative() || ttl.isZero()) {
            throw new IllegalStateException("Expired token");
        }

        return ttl;
    }
    
    private Mono<List<String>> computeSanitizedRolesFromAttributes(Map<String, Object> attrs) {

    	return Mono.fromSupplier(() -> {

            Set<String> rawRoles = new HashSet<>();

            Object realmAccess = attrs.get("realm_access");
            if (realmAccess instanceof Map<?, ?> m && m.get("roles") instanceof Collection<?> rc) {
                rc.forEach(r -> rawRoles.add(String.valueOf(r)));
            }

            Object resAccess = attrs.get("resource_access");
            if (resAccess instanceof Map<?, ?> ra) {
                ra.values().forEach(v -> {
                    if (v instanceof Map<?, ?> mm && mm.get("roles") instanceof Collection<?> c) {
                        c.forEach(r -> rawRoles.add(String.valueOf(r)));
                    }
                });
            }

            Set<String> trustedRoles = props.getNormalizedTrustedRoles();

            return rawRoles.stream()
                    .map(String::toUpperCase)
                    .map(this::sanitizeRole)
                    .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                    .distinct()
                    .filter(trustedRoles::contains)
                    .toList();
        });
    }

    private Mono<List<String>> computeSanitizedRolesReactive(AbstractOAuth2TokenAuthenticationToken<?> auth) {
        // Use cache key derived from principal name + authorities
        OAuth2AuthenticatedPrincipal principal = (OAuth2AuthenticatedPrincipal) auth.getPrincipal();
        String cacheKey = principal.getName() + "::" +
                auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).sorted().collect(Collectors.joining(","));
        List<String> cached = sanitizedRolesCache.getIfPresent(cacheKey);
        if (cached != null) return Mono.just(cached);

        return Mono.fromSupplier(() -> {
            Set<String> trustedRoles = props.getNormalizedTrustedRoles();
            List<String> sanitized = auth.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .map(String::toUpperCase)
                    .map(this::sanitizeRole)
                    .distinct()
                    .filter(trustedRoles::contains)
                    .collect(Collectors.toList());

            List<String> unexpectedRoles = auth.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .map(String::toUpperCase)
                    .map(this::sanitizeRole)
                    .filter(r -> !trustedRoles.contains(r))
                    .collect(Collectors.toList());

            sanitizedRolesCache.put(cacheKey, sanitized);

            if (!unexpectedRoles.isEmpty() && props.isAutoRefreshTrustedRoles()) {
                // trigger refresh async but do not wait (best-effort)
                refreshTrustedRolesAsync().subscribe(
                        null,
                        err -> log.debug("Failed refreshing trusted roles: {}", err.toString())
                );
            }
            return sanitized;
        });
    }

    private String sanitizeRole(String raw) {
        if (raw == null) return "";
        // Remove control characters/newlines and trim; also strip commas to avoid header splitting attacks
        return raw.replaceAll("[\\p{Cntrl}\\n\\r,]+", "").trim();
    }

    private Mono<Void> propagateRoles(ServerWebExchange exchange,
                                      WebFilterChain chain,
                                      String userId,
                                      String jti,
                                      String clientIp,
                                      String traceId,
                                      List<String> sanitizedRoles) {

        String combinedRoles = String.join(",", sanitizedRoles);
        List<String> roleChunks;

        if (combinedRoles.length() > MAX_TOTAL_ROLE_HEADER_SIZE) {
            // compress into single header if too large
            String compressed = Base64.getEncoder().encodeToString(combinedRoles.getBytes(StandardCharsets.UTF_8));
            roleChunks = List.of("COMPRESSED:" + compressed);
            log.warn("[traceId={}] Roles compressed for user {} size={}", traceId, maskUserId(userId), combinedRoles.length());
        } else {
            roleChunks = splitRolesHeader(sanitizedRoles, MAX_ROLE_HEADER_LENGTH);
        }

        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .headers(headers -> {
                    // Remove known sensitive headers (defense-in-depth)
                    headers.remove("X-User-Id");
                    headers.remove("X-Roles");
                    headers.remove("X-Client-Ip");
                    headers.remove("X-Trace-Id");
                    headers.remove("traceparent");

                    // Remove all X-Roles-* headers case-insensitively
                    List<String> keysToRemove = headers.keySet().stream()
                            .filter(h -> h.toLowerCase(Locale.ROOT).startsWith("x-roles-"))
                            .toList();

                    keysToRemove.forEach(headers::remove);

                    // Add sanitized secure headers
                    headers.add("X-User-Id", hashUserId(userId));
                    for (int i = 0; i < roleChunks.size(); i++) {
                        headers.add("X-Roles-" + (i + 1), roleChunks.get(i));
                    }

                    if (clientIp != null && !clientIp.isBlank()) {
                        headers.add("X-Client-Ip", clientIp);
                    }

                    headers.add("X-Trace-Id", traceId);
                    headers.add(
                            "traceparent",
                            "00-" + traceId + "-" +
                            UUID.randomUUID().toString().replace("-", "").substring(0, 16) + "-01"
                    );
                })
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private Mono<Void> refreshTrustedRolesAsync() {
        if (props.getKeycloakRolesEndpoint() == null || props.getKeycloakRolesEndpoint().isBlank()) {
            log.debug("Keycloak roles endpoint not configured - skipping refresh");
            return Mono.empty();
        }
        return keycloakClient.get()
                .uri(props.getKeycloakRolesEndpoint())
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<List<String>>() {})
                .doOnNext(fetchedRoles -> {
                    props.setNormalizedTrustedRoles(fetchedRoles.stream().map(String::toUpperCase).collect(Collectors.toSet()));
                    sanitizedRolesCache.invalidateAll();
                    log.info("Refreshed trusted roles from Keycloak: {}", props.getNormalizedTrustedRoles());
                })
                .doOnError(err -> log.error("Failed to fetch Keycloak roles", err))
                .then();
    }

    private List<String> splitRolesHeader(List<String> roles, int maxLength) {
        List<String> chunks = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        for (String role : roles) {
            if (role == null || role.isBlank()) continue;
            if (sb.length() + role.length() + (sb.length() == 0 ? 0 : 1) > maxLength) {
                chunks.add(sb.toString());
                sb = new StringBuilder();
            }
            if (sb.length() > 0) sb.append(",");
            sb.append(role);
        }
        if (sb.length() > 0) chunks.add(sb.toString());
        return chunks;
    }

    private String maskUserId(String userId) {
        if (userId == null) return "unknown";
        if (userId.contains("@")) {
            int atIdx = userId.indexOf('@');
            return userId.charAt(0) + "***" + userId.substring(atIdx);
        }
        return userId.length() <= 2 ? "**" : userId.charAt(0) + "***";
    }

    private String hashUserId(String userId) {
        if (userId == null) return "unknown";
        return DigestUtils.sha256Hex(userId).substring(0, 16);
    }

    private String hashTokenPrefix(String tokenValue) {
        return DigestUtils.sha256Hex(tokenValue).substring(0, 16);
    }

    // Optional public helpers for eviction used elsewhere
    public void evictTokenIfPresent(String jti) {
        if (jti == null) return;
        tokenExpiryCache.invalidate(jti);
        log.debug("Evicted token cache entry for jti={}", jti);
    }

    public void evictUserIfPresent(String userId) {
        if (userId == null) return;
        String prefix = userId + "::";
        Set<String> keysToEvict = sanitizedRolesCache.asMap().keySet().stream()
                .filter(key -> key.startsWith(prefix))
                .collect(Collectors.toSet());
        if (!keysToEvict.isEmpty()) {
            sanitizedRolesCache.invalidateAll(keysToEvict);
            log.debug("Evicted {} role cache entries for user {}", keysToEvict.size(), userId);
        }
    }
}
