package com.learn.api_gateway.handler;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.learn.api_gateway.config.properties.OpaqueTokenProperties;
import com.learn.api_gateway.filter.ClientIpFilter;
import com.learn.api_gateway.filter.SessionToBearerTokenFilter;
import com.learn.api_gateway.filter.SessionToBearerTokenFilter.DeviceFingerprint;
import com.learn.api_gateway.filter.SessionToBearerTokenFilter.MobileSessionRecord;
import com.learn.api_gateway.resolver.ClientTypeResolver;
import com.learn.api_gateway.resolver.ClientTypeResolver.ClientType;
import com.learn.api_gateway.service.RecaptchaService;
import com.learn.api_gateway.util.ErrorResponseWriter;

import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class OAuthLoginHandler {
	private final RecaptchaService recaptchaService;
	private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
	private final ClientTypeResolver clientTypeResolver;
    private final ObjectMapper objectMapper;
    private final ErrorResponseWriter errorResponseWriter;
    private final OpaqueTokenProperties opaqueTokenProperties;
    private final WebClient keycloakClient;
    
    @Value("${keycloak.auth-server-url}")
    private String keycloakAuthServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${security.oauth2.opaque-token.client-id}")
    private String clientId;

    @Value("${app.oauth2.redirect-uri}")
    private String redirectUri;

    // Optional PKCE config
    @Value("${app.oauth2.pkce-enabled:true}")
    private boolean pkceEnabled;
    
    @Value("${app.oauth2.frontend-origin}")
    private String frontendUri;
    
    public OAuthLoginHandler(
          RecaptchaService recaptchaService,
          ReactiveRedisTemplate<String, String> reactiveRedisTemplate,
          @Qualifier("keycloakWebClient") WebClient keycloakClient,
          OpaqueTokenProperties opaqueTokenProperties,
          ClientTypeResolver clientTypeResolver,
          ObjectMapper objectMapper,
          ErrorResponseWriter errorResponseWriter) {
      this.recaptchaService = recaptchaService;
      this.reactiveRedisTemplate = reactiveRedisTemplate;
      this.keycloakClient = keycloakClient;
      this.opaqueTokenProperties=opaqueTokenProperties;
      this.clientTypeResolver=clientTypeResolver;
      this.objectMapper=objectMapper;
      this.errorResponseWriter = errorResponseWriter;
  }
    
    private static final String ACTIVE_SESSION_PREFIX = "user:%s:active-session";
    private static final String SESSION_VERSION_PREFIX = "user:%s:session-version";
    
    private static final String STATE_PREFIX = "oauth2:state:";
    private static final String PKCE_PREFIX = "oauth2:pkce:";
    private static final String SESSION_PREFIX = "session:";
    
    @Value("${security.session.cookie-name:API-SESSION}")
    private String sessionCookieName;

    @Value("${security.session.ttl-seconds:3600}")
    private long sessionTtlSeconds;

    @Value("${security.session.cookie-domain:}")
    private String sessionCookieDomain;
    
    // Timeout configuration for external calls
    private static final Duration TOKEN_EXCHANGE_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration INTROSPECTION_TIMEOUT = Duration.ofSeconds(5);
	
	public Mono<ServerResponse> login (ServerRequest request) {
		ServerWebExchange exchange = request.exchange();
		String recaptchaToken = request.headers().firstHeader("X-Captcha-Response");
		
		if (isBlank(recaptchaToken)) {
	        return ServerResponse.status(HttpStatus.BAD_REQUEST).build();
	    }

	    return loginInternal(recaptchaToken, exchange)
	            .then(ServerResponse.noContent().build());
	}
	
	public Mono<ServerResponse> callback(ServerRequest request) {

	    ServerWebExchange exchange = request.exchange();

	    String code = request.queryParam("code").orElse(null);
	    String state = request.queryParam("state").orElse(null);

	    return callbackInternal(code, state, exchange)
	            .then(ServerResponse.noContent().build());
	}
	
	private static boolean isBlank(@Nullable String s) {
        return s == null || s.trim().isEmpty();
    }
	
	private Mono<Void> loginInternal(String recaptchaToken, ServerWebExchange exchange) {
		String clientIp = normalizeIp((String) exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP));
        String rateLimitKey = "oauth2:login:ip:" + clientIp;
        
        log.info("----oAuthProxyLogin clientIp proof {}, with rateLimitKey {}",clientIp, rateLimitKey);
        
        int maxAttempts = 5;
        Duration window = Duration.ofMinutes(1);

        ServerHttpResponse resp = exchange.getResponse();

        return reactiveRedisTemplate.opsForValue()
                .increment(rateLimitKey)
                .flatMap(count -> {
                    if (count == 1) {
                        return reactiveRedisTemplate.expire(rateLimitKey, window).thenReturn(count);
                    }
                    return Mono.just(count);
                })
                .flatMap(count -> {

                    // ---- RATE LIMIT (IP-level) ----
                    if (count > maxAttempts) {
                        log.warn("[AUDIT] Rate limit exceeded login IP={}", clientIp);

                        return errorResponseWriter.write(
                                exchange,
                                HttpStatus.TOO_MANY_REQUESTS,
                                "Too many login attempts. Please try again later."
                        );
                    }

                    // ---- CAPTCHA VALIDATION ----
                    return recaptchaService.validate(
                                    recaptchaToken,
                                    clientIp,
                                    "login",
                                    "oauth-proxy:login",
                                    exchange
                            )
                            .flatMap(result -> {

                                switch (result) {

                                    case PASSED:
                                        // continue login flow
                                        break;

                                    case INVALID:
                                        log.warn("[LOGIN] Invalid captcha IP={}", clientIp);
                                        return errorResponseWriter.write(
                                                exchange,
                                                HttpStatus.FORBIDDEN,
                                                "Captcha validation failed: captcha_invalid"
                                        );

                                    case RATE_LIMITED:
                                        log.warn("[LOGIN] Captcha rate limited IP={}", clientIp);
                                        return errorResponseWriter.write(
                                                exchange,
                                                HttpStatus.TOO_MANY_REQUESTS,
                                                "Captcha rate limit exceeded"
                                        );

                                    case PROVIDER_ERROR:
                                        log.error("[LOGIN] Captcha provider error IP={}", clientIp);
                                        return errorResponseWriter.write(
                                                exchange,
                                                HttpStatus.SERVICE_UNAVAILABLE,
                                                "Captcha service temporarily unavailable"
                                        );

                                    default:
                                        log.error("[LOGIN] Unexpected captcha result {}", result);
                                        return errorResponseWriter.write(
                                                exchange,
                                                HttpStatus.INTERNAL_SERVER_ERROR,
                                                "Captcha validation error"
                                        );
                                }

                                // ---- PREPARE STATE + PKCE (UNCHANGED) ----
                                String state = UUID.randomUUID().toString();
                                String nonce = UUID.randomUUID().toString();
                                AtomicReference<String> codeChallengeRef = new AtomicReference<>();
                                Duration stateTtl = Duration.ofMinutes(5);

                                Mono<Void> storeStateMono =
                                        reactiveRedisTemplate.opsForValue()
                                                .set(
                                                        "oauth2:state:" + state,
                                                        "nonce:" + nonce + "|status:NEW",
                                                        stateTtl
                                                )
                                                .then();

                                if (pkceEnabled) {
                                    byte[] verifier = new byte[64];
                                    new SecureRandom().nextBytes(verifier);

                                    String codeVerifier = Base64.getUrlEncoder()
                                            .withoutPadding()
                                            .encodeToString(verifier);

                                    String challenge = Base64.getUrlEncoder()
                                            .withoutPadding()
                                            .encodeToString(DigestUtils.sha256(codeVerifier));

                                    codeChallengeRef.set(challenge);

                                    storeStateMono = storeStateMono.then(
                                            reactiveRedisTemplate.opsForValue()
                                                    .set(
                                                            "oauth2:pkce:" + state,
                                                            codeVerifier,
                                                            stateTtl
                                                    )
                                                    .then()
                                    );
                                }

                                return storeStateMono
                                        .then(Mono.fromSupplier(() -> {

                                            UriComponentsBuilder builder =
                                                    UriComponentsBuilder
                                                            .fromUriString(keycloakAuthServerUrl)
                                                            .pathSegment(
                                                                    "realms",
                                                                    realm,
                                                                    "protocol",
                                                                    "openid-connect",
                                                                    "auth"
                                                            )
                                                            .queryParam("client_id", clientId)
                                                            .queryParam("response_type", "code")
                                                            .queryParam("scope", "openid profile")
                                                            .queryParam("redirect_uri", redirectUri)
                                                            .queryParam("state", state)
                                                            .queryParam("nonce", nonce);

                                            if (pkceEnabled) {
                                                builder.queryParam("code_challenge", codeChallengeRef.get())
                                                       .queryParam("code_challenge_method", "S256");
                                            }

                                            return builder.build(false).toUriString();
                                        }))
                                        .flatMap(redirectUrl -> {
                                            if (resp.isCommitted()) {
                                                return Mono.empty();
                                            }

                                            resp.setStatusCode(HttpStatus.SEE_OTHER);
                                            resp.getHeaders().set(HttpHeaders.LOCATION, redirectUrl);
                                            return resp.setComplete();
                                        });
                            });
                })
                // ---- FINAL SAFETY NET ----
                .onErrorResume(ex -> {
                    log.error("[LOGIN] Unexpected pipeline error", ex);
                    return errorResponseWriter.write(
                            exchange,
                            HttpStatus.INTERNAL_SERVER_ERROR,
                            "Internal authentication error"
                    );
                });
	}
	
	private String normalizeIp(String ip) {
        if (ip == null) return "unknown";
        // normalize IPv6-mapped IPv4
        if (ip.startsWith("::ffff:")) {
            return ip.substring(7);
        }
        return ip;
    }
	
	private Mono<Void> callbackInternal(String code, String state, ServerWebExchange exchange) {
		String traceId = exchange.getAttributeOrDefault("traceId", UUID.randomUUID().toString());
        log.info("[traceId={}] /oauth-proxy/callback called", traceId);

        // Validate presence
        if (isBlank(code) || isBlank(state)) {
            log.warn("[traceId={}] Missing code or state", traceId);
            return redirectWithError(exchange.getResponse(), "invalid_request", HttpStatus.BAD_REQUEST);
        }

        String stateKey = STATE_PREFIX + state;
        String pkceKey = PKCE_PREFIX + state;

        // Step 1: validate state exists and hasn't expired
        return reactiveRedisTemplate.opsForValue().get(stateKey)
                .flatMap(storedState -> {
                    if (isBlank(storedState)) {
                        log.warn("[traceId={}] State missing/expired: {}", traceId, stateKey);
                        return Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN, "invalid_state"));
                    }

                    // optional: storedState may contain nonce or other metadata; you may validate nonce here
                    return Mono.just(storedState);
                })
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN, "invalid_state")))

                // Step 2: retrieve PKCE verifier
                .flatMap(stored -> reactiveRedisTemplate.opsForValue().get(pkceKey)
                        .flatMap(pkceVerifier -> {
                            if (isBlank(pkceVerifier)) {
                                log.warn("[traceId={}] PKCE verifier missing for state {}", traceId, state);
                                return Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN, "pkce_missing"));
                            }
                            return Mono.just(pkceVerifier);
                        }))

                // Step 3: perform token exchange
                .flatMap(pkceVerifier -> exchangeCodeForTokens(code, pkceVerifier, traceId))

                // Step 4: validate tokens (introspection for opaque tokens; or validate JWT signatures/claims for JWTs)
                .flatMap(tokenMap -> validateAccessToken(tokenMap, traceId))

                // Step 5: create opaque session and cleanup state+pkce
                .flatMap(validated -> {
                    ClientType clientType = clientTypeResolver.resolve(exchange);

                    if (clientType == ClientType.MOBILE) {
                        log.info("[traceId={}] OAuth callback resolved MOBILE client", traceId);
                        return respondWithToken(
                                validated, stateKey, pkceKey, exchange, traceId
                        );
                    }

                    log.info("[traceId={}] OAuth callback resolved BROWSER client", traceId);
                    return createSessionAndRedirect(
                            validated, stateKey, pkceKey, exchange, traceId
                    );
                })

                // Errors -> map to user-friendly redirect (avoid leaking internals)
                .onErrorResume(ex -> {
                    if (ex instanceof ResponseStatusException rse) {
                        log.warn("[traceId={}] OAuth callback error: {}", traceId, rse.getReason());
                        return redirectWithError(
                                exchange.getResponse(),
                                rse.getReason(),
                                (HttpStatus) rse.getStatusCode()
                        );
                    }
                    log.error("[traceId={}] Unexpected error in callback", traceId, ex);
                    return redirectWithError(exchange.getResponse(), "server_error", HttpStatus.INTERNAL_SERVER_ERROR);
                });
	}
	
	// Exchange code for tokens (authorization_code grant with PKCE verifier)
    private Mono<Map<String, Object>> exchangeCodeForTokens(String code, String pkceVerifier, String traceId) {
        log.info("[traceId={}] Exchanging code for tokens", traceId);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", redirectUri);
        form.add("code_verifier", pkceVerifier);
        
        String clientId = opaqueTokenProperties
                .getOauth2()
                .getOpaqueToken()
                .getClientId();

        String clientSecret = opaqueTokenProperties
                .getOauth2()
                .getOpaqueToken()
                .getClientSecret();
        String basicAuth = Base64.getEncoder()
                .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));

        return keycloakClient.post()
                .uri("/protocol/openid-connect/token")
                .header(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(HttpHeaders.AUTHORIZATION, "Basic " + basicAuth)
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                .onStatus(HttpStatusCode::is4xxClientError, resp -> {
                    log.warn("[traceId={}] Token endpoint returned 4xx", traceId);
                    return Mono.error(new ResponseStatusException(
                            HttpStatus.UNAUTHORIZED, "token_exchange_failed"));
                })
                .onStatus(HttpStatusCode::is5xxServerError, resp -> {
                    log.error("[traceId={}] Token endpoint returned 5xx", traceId);
                    return Mono.error(new ResponseStatusException(
                            HttpStatus.SERVICE_UNAVAILABLE, "token_exchange_failed"));
                })
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .timeout(TOKEN_EXCHANGE_TIMEOUT)
                .doOnNext(m -> log.debug("[traceId={}] token response keys={}", traceId, m.keySet()));
    }

    private Mono<Void> respondWithToken(Map<String, Object> validated, String stateKey, String pkceKey,
            ServerWebExchange exchange,String traceId) {

        String accessToken = Objects.toString(validated.get("access_token"), null);
        String userId = Objects.toString(validated.get("sub"), null);
              
        if (accessToken == null || userId == null) {
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "no_access_token"));
        }
        
        String deviceId = exchange.getRequest().getHeaders().getFirst("X-Device-Id");
        
        if (isBlank(deviceId)) {
        	return Mono.error(new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "missing_device_id"));
        }
        
        String ip = Optional.ofNullable(exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP))
                .map(Object::toString)
                .orElse("unknown");
        
        // Generate gateway opaque token
        String mobileToken = "mob_" + UUID.randomUUID(); //client-facing
        String mobileSessionId = "ms_" + UUID.randomUUID(); //internal only
        String redisKey = "mobile:access:" + mobileToken;
        String sessionVersionKey = SESSION_VERSION_PREFIX.formatted(userId);
        
        return reactiveRedisTemplate.opsForValue()
                // bump session version (same as browser)
                .increment(sessionVersionKey)
                .map(v -> v != null ? v : 1L)

                // store full mobile session record
                .flatMap(version -> {
                    MobileSessionRecord record = new MobileSessionRecord(
                            accessToken,
                            userId,
                            mobileSessionId,
                            deviceId,
                            ip,
                            version.intValue()
                    );

                    final String json;
                    try {
                        json = objectMapper.writeValueAsString(record);
                    } catch (Exception e) {
                        return Mono.error(e);
                    }

                    return reactiveRedisTemplate.opsForValue()
                            .set(redisKey, json, Duration.ofMinutes(15));
                })
                .then(reactiveRedisTemplate.delete(stateKey, pkceKey))
                .then(Mono.defer(() -> {

                    ServerHttpResponse resp = exchange.getResponse();
                    resp.setStatusCode(HttpStatus.OK);
                    resp.getHeaders().setContentType(MediaType.APPLICATION_JSON);

                    byte[] body = """
                    {
                      "access_token": "%s",
                      "token_type": "Bearer",
                      "expires_in": 900
                    }
                    """.formatted(mobileToken).getBytes(StandardCharsets.UTF_8);

                    return resp.writeWith(
                            Mono.just(resp.bufferFactory().wrap(body))
                    );
                }));
    }
    
    // Validate access token using introspection (opaque tokens) or JWT verification if token contains '.'
    private Mono<Map<String, Object>> validateAccessToken(Map<String, Object> tokenResponse, String traceId) {
        String accessToken = Objects.toString(tokenResponse.get("access_token"), null);
        if (isBlank(accessToken)) {
            log.warn("[traceId={}] token response missing access_token", traceId);
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "no_access_token"));
        }

        // Quick heuristic: JWTs contain two dots
        if (accessToken.chars().filter(ch -> ch == '.').count() == 2) {
        	String userId = extractUserIdFromJwt(accessToken);
            if (userId == null) {
                log.error("[traceId={}] JWT missing sub claim", traceId);
                return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid_token"));
            }

            tokenResponse.put("active", true);
            tokenResponse.put("sub", userId);

            return Mono.just(tokenResponse);
        }

        // Opaque token -> introspect
        return keycloakClient.post()
                .uri("/protocol/openid-connect/token/introspect")
                .header(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(BodyInserters.fromFormData("token", accessToken))
                .retrieve()
                .bodyToMono(Map.class)
                .timeout(INTROSPECTION_TIMEOUT)
                .flatMap(introspect -> {
                    Boolean active = (Boolean) introspect.getOrDefault("active", Boolean.FALSE);
                    if (!Boolean.TRUE.equals(active)) {
                        log.warn("[traceId={}] introspection inactive", traceId);
                        return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid_token"));
                    }
                    // Merge introspection result into tokenResponse for later use
                    tokenResponse.putAll(introspect);
                    return Mono.just(tokenResponse);
                });
    }
    
    private Mono<Void> createSessionAndRedirect(Map<String, Object> validated, String stateKey, String pkceKey,
		            ServerWebExchange exchange, String traceId) {
    	String accessToken = Objects.toString(validated.get("access_token"), null);
        if (accessToken == null) {
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED));
        }
        String userId = Objects.toString(validated.get("sub"), null);
        if (userId == null) {
            return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "missing_user_id"));
        }
        
        String sessionId = generateSessionId();
        String sessionKey = SESSION_PREFIX + sessionId;
        
        String activeSessionKey = ACTIVE_SESSION_PREFIX.formatted(userId);
        String sessionVersionKey = SESSION_VERSION_PREFIX.formatted(userId);
        
        String ip = Optional.ofNullable(exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP))
                .map(Object::toString)
                .orElse("unknown");

        String uaHash = DigestUtils.sha256Hex(
                Objects.toString(
                        exchange.getRequest().getHeaders().getFirst(HttpHeaders.USER_AGENT),
                        "unknown"
                )
        );
        return reactiveRedisTemplate.opsForValue()
                // STEP 1: invalidate previous session (if any)
                .get(activeSessionKey)
                .flatMap(oldSessionId -> {
                    if (StringUtils.hasText(oldSessionId)) {
                        log.info("[traceId={}] Invalidating previous session {} for user {}",
                                traceId, oldSessionId, userId);
                        return reactiveRedisTemplate.delete(SESSION_PREFIX + oldSessionId);
                    }
                    return Mono.empty();
                })
                // STEP 2: bump session version (defense-in-depth)
                .then(
                    reactiveRedisTemplate.opsForValue()
                        .increment(sessionVersionKey)
                        .map(v -> v != null ? v : 1L)
                )
                // STEP 3: store new session with version
                .flatMap(newVersion -> {
                	DeviceFingerprint deviceFingerprint =
                	        new DeviceFingerprint(
                	                exchange.getRequest().getHeaders().getFirst("X-Device-Id"),
                	                uaHash,
                	                exchange.getRequest().getHeaders().getFirst("X-Platform"),
                	                exchange.getRequest().getHeaders().getFirst("X-App-Version")
                	        );
                	
                	SessionToBearerTokenFilter.SessionRecord record =
                            new SessionToBearerTokenFilter.SessionRecord(
                                    accessToken,
                                    userId,
                                    ip,
                                    uaHash,
                                    newVersion.intValue(),
                                    deviceFingerprint,
                                    Instant.now(),
                                    Instant.now()
                            );
                	
                	final String json;
                    try {
                        json = objectMapper.writeValueAsString(record);
                    } catch (Exception e) {
                        log.error("Failed to serialize session", e);
                        return Mono.error(new IllegalStateException("Session serialization failed"));
                    }
                    
                    return reactiveRedisTemplate.opsForValue()
                            .set(sessionKey, json, Duration.ofSeconds(sessionTtlSeconds))
                            .then(
                                reactiveRedisTemplate.opsForValue()
                                    .set(activeSessionKey, sessionId,
                                            Duration.ofSeconds(sessionTtlSeconds))
                            );
                })
                // STEP 4: cleanup OAuth artifacts
                .then(reactiveRedisTemplate.delete(stateKey, pkceKey))
                // STEP 5: issue cookie
                .then(Mono.defer(() -> {
                    ResponseCookie cookie = ResponseCookie.from(sessionCookieName, sessionId)
                            .httpOnly(true)
                            .secure(true)
                            .sameSite("Strict")
                            .path("/")
                            .maxAge(Duration.ofSeconds(sessionTtlSeconds))
                            .build();
                    
                    ServerHttpResponse resp = exchange.getResponse();
                    resp.addCookie(cookie);
                    resp.setStatusCode(HttpStatus.SEE_OTHER);
                    resp.getHeaders().set(
                            HttpHeaders.LOCATION,
                            frontendUri + "/auth/sso/success"
                    );
                    return resp.setComplete();
                }));
	}
    
    private Mono<Void> redirectWithError(ServerHttpResponse resp, String errorCode, HttpStatus status) {
        // Minimal information leak: only send an opaque error code the frontend can map to friendly message
        String redirectTo = frontendUri + "/auth/sso/error?e=" + urlSafe(errorCode);
        return Mono.defer(() -> {
            if (resp.isCommitted()) {
                return Mono.empty(); // cannot redirect anymore
            }

            resp.setStatusCode(HttpStatus.SEE_OTHER);
            resp.getHeaders().set(HttpHeaders.LOCATION, redirectTo);
            return resp.setComplete();
        });
    }
    
    private static String generateSessionId() {
        byte[] rnd = UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(rnd);
    }

    private static String urlSafe(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
    
    private String extractUserIdFromJwt(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length != 3) {
                return null;
            }

            String payloadJson = new String(
                    Base64.getUrlDecoder().decode(parts[1]),
                    StandardCharsets.UTF_8
            );

            JsonNode node = objectMapper.readTree(payloadJson);
            return node.path("sub").asText(null);

        } catch (Exception e) {
            log.error("Failed to decode JWT", e);
            return null;
        }
    }
}
