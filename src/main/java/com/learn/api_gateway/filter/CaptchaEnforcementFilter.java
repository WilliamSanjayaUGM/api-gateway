package com.learn.api_gateway.filter;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.ResolvableType;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.codec.FormHttpMessageReader;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.learn.api_gateway.config.properties.RecaptchaConfigProperties;
import com.learn.api_gateway.dto.CaptchaResult;
import com.learn.api_gateway.service.AuditService;
import com.learn.api_gateway.service.GeoIpService;
import com.learn.api_gateway.service.HmacService;
import com.learn.api_gateway.service.RecaptchaService;
import com.learn.api_gateway.util.ErrorResponseWriter;
import com.learn.api_gateway.util.GatewayUtil;
import com.learn.api_gateway.util.TraceConstants;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * login (any /oauth-proxy) endpoint, should not be handled by this filter
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CaptchaEnforcementFilter implements GlobalFilter, Ordered{
	
	private final RecaptchaService recaptchaService;
    private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
    private final HmacService hmacService;
    private final RecaptchaConfigProperties props;
    private final GatewayUtil gatewayUtil;
    private final ObjectMapper objectMapper;
    private final AuditService auditService;
    private final ErrorResponseWriter errorResponseWriter;
    private final GeoIpService geoIpService;

    private final FormHttpMessageReader formReader = new FormHttpMessageReader();

    private static final String FAILURE_KEY_PREFIX = "login:failures:";
    private static final String REPLAY_KEY_PREFIX = "captcha:used:";

    @Value("${bucket4j.timeout-ms:1000}")
    private long redisTimeoutMs;

    enum ResetMode {ON_200, ON_SUCCESS}

    @Override
    public int getOrder() {
        return -730;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    	if (exchange.getRequest().getMethod() == HttpMethod.OPTIONS) {
            return chain.filter(exchange);
        }

        String path = exchange.getRequest().getURI().getPath();
        String clientIp = maskIp(getResolvedClientIp(exchange));
        
        log.info("------------CaptchaEnforcementFilter is checked, path {}, clientIp {}--------", path, clientIp);
        
        if (path.startsWith("/realms/") &&
        	path.contains("/protocol/openid-connect/") &&
        	(path.contains("/auth") || path.contains("/token"))) {

        	log.info("Skipping CaptchaEnforcementFilter for Keycloak SSO path {}", path);
        	return chain.filter(exchange);
        }
        
        if (path.startsWith("/oauth-proxy/")) {
            log.debug("CaptchaEnforcementFilter bypassed for oauth-proxy path={}", path);
            return chain.filter(exchange);
        }

        if (isTokenEndpoint(path)) {
            return gatewayUtil.cacheRequestBody(exchange)
                    .flatMap(mutatedEx -> formReader.readMono(
                                    ResolvableType.forClassWithGenerics(MultiValueMap.class, String.class, String.class),
                                    mutatedEx.getRequest(),
                                    Collections.emptyMap())
                            .defaultIfEmpty(new LinkedMultiValueMap<>())
                            .flatMap(params -> {
                                String username = Optional.ofNullable(params.getFirst("username"))
                                        .map(u -> maskUser(u.toLowerCase(Locale.ROOT))).orElse("");
                                String clientId = Optional.ofNullable(params.getFirst("client_id"))
                                        .map(c -> c.toLowerCase(Locale.ROOT)).orElse("");

                                String ipKeyRaw = clientIp;
                                String userKeyRaw = clientIp + ":" + clientId + ":" + username;

                                return Mono.zip(hmacService.sign(ipKeyRaw, "gateway"),
                                                hmacService.sign(userKeyRaw, "gateway"))
                                        .flatMap(tuple -> {
                                            String ipKey = tuple.getT1();
                                            String userKey = tuple.getT2();

                                            return shouldRequireCaptcha(ipKey, true)
                                                    .zipWith(shouldRequireCaptcha(userKey, true))
                                                    .flatMap(requireTuple -> {
                                                        boolean requireCaptcha = requireTuple.getT1() || requireTuple.getT2();
                                                        if (!requireCaptcha) {
                                                        	return isCaptchaVerified(mutatedEx)
                                                                    .flatMap(verified -> {
                                                                        if (verified) {
                                                                            log.info("Captcha previously verified → skipping captcha enforcement");
                                                                            return chainWithOutcome(mutatedEx, chain, ResetMode.ON_SUCCESS, userKey, ipKey);
                                                                        }

                                                                        // not verified → enforce now
                                                                        return enforceCaptcha(mutatedEx,chain,clientIp,props.getLoginAction(),new String[]{userKey, ipKey},
                                                                                params,ResetMode.ON_SUCCESS);
                                                                    });
                                                        }
                                                        return enforceCaptcha(mutatedEx,chain,clientIp,props.getLoginAction(),new String[]{userKey, ipKey},
                                                                params,ResetMode.ON_SUCCESS);
                                                    });
                                        })
                                        .onErrorResume(ex -> {
                                            log.error("❌ HMAC generation error: {}", ex.toString());
                                            return captchaForbidden(mutatedEx, "hmac_error", isTokenEndpoint(path));
                                        });
                            }));
        }

        if (path.startsWith("/auth/signup")) {
        	return isCaptchaVerified(exchange)
        	        .flatMap(verified -> {
        	            if (verified) {
        	                log.info("Captcha previously verified → skipping captcha enforcement (signup)");
        	                return chain.filter(exchange);
        	            }
        	            
        	            return hmacService.sign(clientIp, "gateway")
        	                    .flatMap(ipKey -> enforceCaptcha(exchange, chain, clientIp, props.getSignupAction(),
        	                            new String[]{ipKey}, null, ResetMode.ON_SUCCESS));
        	        })
        	        .onErrorResume(ex -> captchaForbidden(exchange, "hmac_error", false));
        }

        return chain.filter(exchange);
    }

    private String getResolvedClientIp(ServerWebExchange exchange) {

        Object ipAttr = exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP);
        if (ipAttr instanceof String ip && !ip.isBlank()) {
            return ip;
        }

        String activeProfile = System.getProperty("spring.profiles.active", "default");
        if (!activeProfile.equalsIgnoreCase("prod")
                && !activeProfile.equalsIgnoreCase("production")) {

            String devFallback = Optional.ofNullable(exchange.getRequest().getRemoteAddress())
                    .map(addr -> addr.getAddress())
                    .map(InetAddress::getHostAddress)
                    .orElse("127.0.0.1");

            log.warn("DEV MODE: Falling back to remoteAddress IP = {}", devFallback);
            return devFallback;
        }

        log.error("SECURITY: Client IP not resolved by ClientIpFilter");
        throw new IllegalStateException("Client IP unavailable");
    }

    private Mono<Void> enforceCaptcha(ServerWebExchange exchange,
                                      GatewayFilterChain chain,
                                      String clientIp,
                                      String action,
                                      String[] identifiers,
                                      MultiValueMap<String, String> formParams,
                                      ResetMode resetMode) {
    	
    	return extractCaptchaToken(exchange, formParams)
                .switchIfEmpty(
                        captchaForbidden(
                                exchange,
                                "captcha_missing",
                                isTokenEndpoint(exchange.getRequest().getPath().value())
                        ).then(Mono.empty())
                )
                .flatMap(captchaToken -> {

                    String replayKey =
                            REPLAY_KEY_PREFIX + DigestUtils.sha256Hex(captchaToken).substring(0, 32);

                    return recaptchaService
                            .validate(captchaToken, clientIp, action, action, exchange)
                            .flatMap(result -> {

                                /* =======================
                                 * CAPTCHA PASSED
                                 * ======================= */
                                if (result == CaptchaResult.PASSED) {

                                    auditService.auditInfo(
                                            "CAPTCHA_PASSED",
                                            null,
                                            clientIp,
                                            exchange.getRequest().getPath().value(),
                                            "Captcha passed",
                                            Map.of("action", action)
                                    );

                                    String fingerprint =
                                            DigestUtils.sha256Hex(
                                                    clientIp + "|" +
                                                    exchange.getRequest()
                                                            .getHeaders()
                                                            .getFirst("User-Agent")
                                            ).substring(0, 32);

                                    String verifiedKey = "captcha:verified:" + fingerprint;

                                    Mono<Void> persistCaptchaState =
                                            reactiveRedisTemplate.opsForValue()
                                                    .set(
                                                            replayKey,
                                                            "1",
                                                            props.getRateLimit().getFailureWindow()
                                                    )
                                                    .then(
                                                            reactiveRedisTemplate.opsForValue()
                                                                    .set(
                                                                            verifiedKey,
                                                                            "1",
                                                                            Duration.ofMinutes(
                                                                                    props.getBypassMinutes()
                                                                            )
                                                                    )
                                                    )
                                                    .then();

                                    /*
                                     * IMPORTANT:
                                     * - Let downstream fully control response
                                     * - Do NOT commit response here
                                     * - Only update Redis AFTER downstream completes
                                     */
                                    return persistCaptchaState
                                            .then(
                                                    chain.filter(exchange)
                                            )
                                            .then(Mono.defer(() -> {
                                                HttpStatusCode status =
                                                        exchange.getResponse().getStatusCode();

                                                if (status == null || identifiers == null) {
                                                    return Mono.empty();
                                                }

                                                boolean success =
                                                        resetMode == ResetMode.ON_200
                                                                ? status.value() == 200
                                                                : status.is2xxSuccessful();

                                                if (success) {
                                                    return Flux.fromArray(identifiers)
                                                            .flatMap(id ->
                                                                    reactiveRedisTemplate.delete(
                                                                            FAILURE_KEY_PREFIX + id
                                                                    )
                                                            )
                                                            .then();
                                                }

                                                if (status.value() == 400 || status.value() == 401) {
                                                    return Flux.fromArray(identifiers)
                                                            .flatMap(this::recordFailure)
                                                            .then();
                                                }

                                                return Mono.empty();
                                            }));
                                }

                                /* =======================
                                 * CAPTCHA INVALID
                                 * ======================= */
                                if (result == CaptchaResult.INVALID) {

                                    auditService.auditWarn(
                                            "CAPTCHA_FAILED",
                                            null,
                                            clientIp,
                                            exchange.getRequest().getPath().value(),
                                            "Captcha invalid",
                                            Map.of("action", action)
                                    );

                                    return captchaForbidden(
                                            exchange,
                                            "captcha_invalid",
                                            isTokenEndpoint(
                                                    exchange.getRequest().getPath().value()
                                            )
                                    );
                                }

                                /* =======================
                                 * CAPTCHA RATE LIMITED
                                 * ======================= */
                                if (result == CaptchaResult.RATE_LIMITED) {

                                    auditService.auditWarn(
                                            "CAPTCHA_RATE_LIMITED",
                                            null,
                                            clientIp,
                                            exchange.getRequest().getPath().value(),
                                            "Captcha rate limited",
                                            Map.of("action", action)
                                    );

                                    return captchaForbidden(
                                            exchange,
                                            "captcha_rate_limited",
                                            isTokenEndpoint(
                                                    exchange.getRequest().getPath().value()
                                            )
                                    );
                                }

                                /* =======================
                                 * PROVIDER ERROR
                                 * ======================= */
                                if (result == CaptchaResult.PROVIDER_ERROR) {

                                    auditService.auditError(
                                            "CAPTCHA_PROVIDER_ERROR",
                                            null,
                                            clientIp,
                                            exchange.getRequest().getPath().value(),
                                            "Captcha provider error",
                                            Map.of("action", action)
                                    );

                                    /*
                                     * FAIL-OPEN:
                                     * - Do NOT touch response
                                     * - Let downstream error propagate
                                     */
                                    if (!props.isFailClosedOnValidationError()) {
                                        return chain.filter(exchange);
                                    }

                                    /*
                                     * FAIL-CLOSED:
                                     * - Gateway owns response
                                     */
                                    return captchaForbidden(
                                            exchange,
                                            "captcha_provider_error",
                                            isTokenEndpoint(
                                                    exchange.getRequest().getPath().value()
                                            )
                                    );
                                }

                                /* =======================
                                 * SAFETY NET
                                 * ======================= */
                                log.error("Unexpected CaptchaResult={}", result);

                                return captchaForbidden(
                                        exchange,
                                        "captcha_error",
                                        isTokenEndpoint(
                                                exchange.getRequest().getPath().value()
                                        )
                                );
                            });
                });
    }

    private Mono<String> extractCaptchaToken(ServerWebExchange exchange, MultiValueMap<String, String> formParams) {        
    	// 1. Header
        String headerToken = exchange.getRequest().getHeaders().getFirst("X-Captcha-Response");
        if (headerToken != null && !headerToken.isBlank()) {
            log.info("extractCaptchaToken - token from header: {}", headerToken);
            return Mono.just(headerToken);
        }

        // 2. Query param (e.g. /auth/signup?g-recaptcha-response=xxx)
        String queryToken = exchange.getRequest().getQueryParams().getFirst("g-recaptcha-response");
        if (queryToken != null && !queryToken.isBlank()) {
            log.info("extractCaptchaToken - token from query param: {}", queryToken);
            return Mono.just(queryToken);
        }

        // 3. Form field (for token endpoint)
        if (formParams != null) {
            String bodyToken = formParams.getFirst("g-recaptcha-response");
            if (bodyToken != null && !bodyToken.isBlank()) {
                log.info("extractCaptchaToken - token from form body: {}", bodyToken);
                return Mono.just(bodyToken);
            }
        }

        // 4. JSON body (for /auth/signup)
        return gatewayUtil.cacheRequestBody(exchange)
                .flatMap(mutated -> gatewayUtil.getCachedRequestBodyAsString(mutated))
                .flatMap(body -> {
                    try {
                        JsonNode node = objectMapper.readTree(body);
                        String parsed = node.path("g-recaptcha-response").asText(null);
                        if (parsed != null && !parsed.isBlank()) {
                            log.info("extractCaptchaToken - token from JSON body: {}", parsed);
                            return Mono.just(parsed);
                        }
                        return Mono.empty();
                    } catch (Exception e) {
                        log.debug("Failed to parse JSON captcha body: {}", e.getMessage());
                        return Mono.empty();
                    }
                })
                .switchIfEmpty(Mono.defer(() -> {
                    log.warn("extractCaptchaToken - NO TOKEN FOUND!");
                    return Mono.empty();
                }));
    }

    private boolean isTokenEndpoint(String path) {
        return path.startsWith("/realms/") && path.contains("/protocol/openid-connect/token");
    }
    
    private Mono<Boolean> isCaptchaVerified(ServerWebExchange exchange) {
        String clientIp = exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP);

        if (clientIp == null || clientIp.isBlank() || "unknown".equalsIgnoreCase(clientIp)) {
            log.warn("Captcha verification skipped: client IP unresolved");
            return Mono.just(false); // force captcha instead of crash
        }

        String ua = Optional.ofNullable(exchange.getRequest().getHeaders().getFirst("User-Agent"))
                .orElse("unknown");

        String fingerprint = DigestUtils.sha256Hex(clientIp + "|" + ua).substring(0, 32);
        String redisKey = "captcha:verified:" + fingerprint;

        return reactiveRedisTemplate.hasKey(redisKey)
                .onErrorResume(ex -> {
                    log.error("Captcha verification Redis failure: {}", ex.toString());
                    return Mono.just(false); // FAIL-CLOSED
                });
    }

    private Mono<Boolean> shouldRequireCaptcha(String identifier, boolean defaultDecision) {
        String traceId = Optional.ofNullable(MDC.get(TraceConstants.TRACE_ID_CONTEXT_KEY)).orElse("N/A");
        String key = FAILURE_KEY_PREFIX + identifier;
        long now = Instant.now().toEpochMilli();
        long windowStart = now - props.getRateLimit().getFailureWindow().toMillis();

        String script = """
                redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, ARGV[1])
                local cnt = redis.call('ZCOUNT', KEYS[1], ARGV[1], ARGV[2])
                return cnt
                """;

        return reactiveRedisTemplate.execute(RedisScript.of(script, Long.class),
                        Collections.singletonList(key), String.valueOf(windowStart), String.valueOf(now))
                .next()
                .flatMap(count -> reactiveRedisTemplate.expire(key, props.getRateLimit().getFailureWindow())
                        .thenReturn(count >= props.getRateLimit().getMaxFailuresBeforeCaptcha()))
                .timeout(Duration.ofMillis(redisTimeoutMs))
                .onErrorResume(ex -> {
                    log.warn("[traceId={}] Redis captcha check failed for {}: {}, failClosed={}",
                            traceId, key, ex.toString(), props.isFailClosedOnRedisError());
                    return Mono.just(props.isFailClosedOnRedisError() ? defaultDecision : false);
                });
    }

    private Mono<Void> chainWithOutcome(ServerWebExchange exchange,
                                        GatewayFilterChain chain,
                                        ResetMode resetMode,
                                        String... identifiers) {
    	 return chain.filter(exchange)
    	            .then(Mono.defer(() -> {
    	                HttpStatusCode status = exchange.getResponse().getStatusCode();
    	                if (status == null) {
    	                    log.warn("[traceId={}] chainWithOutcome - response status is null", 
    	                            Optional.ofNullable(exchange.getAttribute(TraceConstants.TRACE_ID_CONTEXT_KEY)).orElse("N/A"));
    	                    return Mono.empty();
    	                }

    	                boolean success = switch (resetMode) {
    	                    case ON_200 -> status.value() == 200;
    	                    case ON_SUCCESS -> status.is2xxSuccessful();
    	                };

    	                if (success) {
    	                    log.info("[traceId={}] chainWithOutcome - success status={}", 
    	                             Optional.ofNullable(exchange.getAttribute(TraceConstants.TRACE_ID_CONTEXT_KEY)).orElse("N/A"), status.value());
    	                    return Flux.fromArray(identifiers)
    	                            .flatMap(id -> reactiveRedisTemplate.delete(FAILURE_KEY_PREFIX + id))
    	                            .then();
    	                }

    	                if (status.value() == 400 || status.value() == 401) {
    	                    log.info("[traceId={}] chainWithOutcome - failure status={}", 
    	                             Optional.ofNullable(exchange.getAttribute(TraceConstants.TRACE_ID_CONTEXT_KEY)).orElse("N/A"), status.value());
    	                    return Flux.fromArray(identifiers)
    	                            .flatMap(this::recordFailure)
    	                            .then();
    	                }

    	                log.debug("[traceId={}] chainWithOutcome - non-handled status={}", 
    	                          Optional.ofNullable(exchange.getAttribute(TraceConstants.TRACE_ID_CONTEXT_KEY)).orElse("N/A"), status.value());
    	                return Mono.empty();
    	            }))
    	            .doOnError(err -> log.error("Downstream error during login flow: {}", err.toString()));
    }

    private Mono<Void> recordFailure(String identifier) {
        String key = FAILURE_KEY_PREFIX + identifier;
        long now = Instant.now().toEpochMilli();
        return reactiveRedisTemplate.opsForZSet().add(key, String.valueOf(now), now)
                .then(reactiveRedisTemplate.expire(key, props.getRateLimit().getFailureWindow()))
                .then();
    }

    private Mono<Void> captchaForbidden(ServerWebExchange exchange, String reason, boolean isTokenEndpoint) {

        String traceId = Optional.ofNullable(
                exchange.getAttribute(TraceConstants.TRACE_ID_CONTEXT_KEY)
        ).map(Object::toString).orElse("N/A");

        
        final String clientIp = Optional.ofNullable(exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP))
                .map(Object::toString)
                .filter(ip -> !ip.isBlank())
                .orElse("unknown");

        String userAgent = Optional.ofNullable(
                exchange.getRequest().getHeaders().getFirst("User-Agent")
        ).orElse("unknown");

        String userId = Optional.ofNullable(
                exchange.getRequest().getHeaders().getFirst("X-User-Id")
        ).orElse("anonymous");

        log.warn("[traceId={}] CAPTCHA BLOCKED reason={} ip={}", traceId, reason, clientIp);

        return geoIpService.resolveCountry(clientIp)
                .defaultIfEmpty("UNKNOWN")
                .onErrorReturn("UNKNOWN")
                .flatMap(country -> {

                    auditService.auditWarn(
                            "CAPTCHA_BLOCKED",
                            userId,
                            clientIp,
                            exchange.getRequest().getURI().getPath(),
                            "Captcha validation failed: " + reason,
                            Map.of(
                                    "traceId", traceId,
                                    "country", country,
                                    "userAgent", userAgent
                            )
                    );

                    HttpStatus status = isTokenEndpoint
                            ? HttpStatus.BAD_REQUEST
                            : HttpStatus.FORBIDDEN;

                    return errorResponseWriter.write(
                            exchange,
                            status,
                            "Captcha validation failed: " + reason
                    );
                });
    }

    private String maskIp(String ip) {
        if (ip == null) return "unknown";
        int idx = ip.lastIndexOf(".");
        return (idx > 0) ? ip.substring(0, idx) + ".*" : ip;
    }

    private String maskUser(String username) {
        if (username == null || username.length() < 3) return "us***";
        return username.substring(0, 2) + "***" + username.charAt(username.length() - 1);
    }
}
