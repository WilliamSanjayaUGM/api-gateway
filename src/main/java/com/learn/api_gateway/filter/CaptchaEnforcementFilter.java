package com.learn.api_gateway.filter;

import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import javax.net.ssl.SSLHandshakeException;

import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
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
import com.learn.api_gateway.dto.CanonicalSecurityIdentity;
import com.learn.api_gateway.dto.CaptchaResult;
import com.learn.api_gateway.service.AuditService;
import com.learn.api_gateway.service.GeoIpService;
import com.learn.api_gateway.service.HmacService;
import com.learn.api_gateway.service.RecaptchaService;
import com.learn.api_gateway.util.ErrorResponseWriter;
import com.learn.api_gateway.util.GatewayUtil;
import com.learn.api_gateway.util.IpUtil;
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
    private final IpUtil ipUtil;

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
        
        log.info("-----CaptchaEnforcementFilter run for path {}, clientIp {}", path, clientIp);

        if (path.startsWith("/realms/")
                && path.contains("/protocol/openid-connect/")
                && (path.contains("/auth") || path.contains("/token"))) {

            log.info("Skipping CaptchaEnforcementFilter for Keycloak SSO path {}", path);
            return chain.filter(exchange);
        }

        if (path.startsWith("/oauth-proxy/")) {
            return chain.filter(exchange);
        }

        if (isTokenEndpoint(path)) {
            return gatewayUtil.cacheRequestBody(exchange)
                    .flatMap(mutated ->
                            formReader.readMono(
                                            ResolvableType.forClassWithGenerics(
                                                    MultiValueMap.class, String.class, String.class),
                                            mutated.getRequest(),
                                            Collections.emptyMap())
                                    .defaultIfEmpty(new LinkedMultiValueMap<>())
                                    .flatMap(params -> {

                                        String username = Optional.ofNullable(params.getFirst("username"))
                                                .map(u -> maskUser(u.toLowerCase(Locale.ROOT)))
                                                .orElse("");

                                        String clientId = Optional.ofNullable(params.getFirst("client_id"))
                                                .map(String::toLowerCase)
                                                .orElse("");

                                        return Mono.zip(
                                                        signIdentity(mutated, clientIp,
                                                                props.getLoginAction(), null, null, path),
                                                        signIdentity(mutated, clientIp,
                                                                props.getLoginAction(), clientId, username, path)
                                                )
                                                .flatMap(tuple -> {

                                                    String ipKey   = tuple.getT1();
                                                    String userKey = tuple.getT2();

                                                    return shouldRequireCaptcha(ipKey, true)
                                                            .zipWith(shouldRequireCaptcha(userKey, true))
                                                            .flatMap(req -> {

                                                                boolean requireCaptcha =
                                                                        req.getT1() || req.getT2();

                                                                if (!requireCaptcha) {
                                                                    return isCaptchaVerified(
                                                                            mutated,
                                                                            props.getLoginAction(),
                                                                            clientId,
                                                                            username
                                                                    ).flatMap(verified -> {
                                                                        if (verified) {
                                                                            return chainWithOutcome(
                                                                                    mutated,
                                                                                    chain,
                                                                                    ResetMode.ON_SUCCESS,
                                                                                    userKey,
                                                                                    ipKey
                                                                            );
                                                                        }
                                                                        return enforceCaptcha(
                                                                                mutated,
                                                                                chain,
                                                                                clientIp,
                                                                                props.getLoginAction(),
                                                                                new String[]{userKey, ipKey},
                                                                                params,
                                                                                ResetMode.ON_SUCCESS,
                                                                                clientId,
                                                                                username
                                                                        );
                                                                    });
                                                                }

                                                                return enforceCaptcha(
                                                                        mutated,
                                                                        chain,
                                                                        clientIp,
                                                                        props.getLoginAction(),
                                                                        new String[]{userKey, ipKey},
                                                                        params,
                                                                        ResetMode.ON_SUCCESS,
                                                                        clientId,
                                                                        username
                                                                );
                                                            });
                                                });
                                    }));
        }
        
        if (path.startsWith("/auth/signup")) {
        	// Stable identity for signup flow (no client_id / username yet)
            final String signupClientId = "signup";
            final String signupUsername = "anonymous";
            
            return isCaptchaVerified(
                    exchange,
                    props.getSignupAction(),
                    signupClientId,
                    signupUsername
            )
            .flatMap(verified -> {
                if (verified) {
                    log.info("Captcha previously verified → skipping captcha enforcement (signup)");
                    return chain.filter(exchange);
                }

                return hmacService.sign(clientIp, "gateway")
                        .flatMap(ipKey ->
                                enforceCaptcha(exchange, chain,clientIp, props.getSignupAction(),
                                		new String[]{ipKey}, null, ResetMode.ON_SUCCESS, signupClientId,
                                        signupUsername
                                )
                        );
            })
            .onErrorResume(SSLHandshakeException.class, ex ->
		            errorResponseWriter.write(
		                exchange,
		                HttpStatus.BAD_GATEWAY,
		                "Upstream TLS failure"
		            )
		    );
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

    private Mono<Void> enforceCaptcha(
            ServerWebExchange exchange,
            GatewayFilterChain chain,
            String clientIp,
            String action,
            String[] identifiers,
            MultiValueMap<String, String> formParams,
            ResetMode resetMode,
            String clientId,
            String username) {

        return extractCaptchaToken(exchange, formParams)
        	.switchIfEmpty(Mono.defer(() -> {
        		log.warn(
        				"[Captcha] MISSING TOKEN action={} ip={} clientId={} username={}",
        	            action, clientIp, clientId, username
        	    );
        	    return Mono.error(new MissingCaptchaException());
        	 }))
            .flatMap(captchaToken -> {

                String replayKeySource =
                        props.getEnvironmentSalt() + "|" +
                        exchange.getRequest().getURI().getScheme() + "|" +
                        action + "|" +
                        ipUtil.normalizeIp(clientIp) + "|" +
                        clientId + "|" +
                        username + "|" +
                        DigestUtils.sha256Hex(captchaToken);

                String replayKey =
                        REPLAY_KEY_PREFIX +
                        DigestUtils.sha256Hex(replayKeySource).substring(0, 32);

                log.info(
                    "[Captcha] TOKEN FOUND action={} ip={} replayKey={}",
                    action, clientIp, replayKey
                );

                return recaptchaService
                        .validate(captchaToken, clientIp, action, action, exchange)
                        .doOnNext(result ->
                            log.info(
                                "[Captcha] VALIDATION RESULT={} action={} ip={}",
                                result, action, clientIp
                            )
                        )
                        .flatMap(result -> {

                            if (result != CaptchaResult.PASSED) {
                                log.warn(
                                    "[Captcha] INVALID RESULT={} action={} ip={}",
                                    result, action, clientIp
                                );
                                return Mono.error(new InvalidCaptchaException());
                            }

                            String verifiedKey =
                                    "captcha:verified:" +
                                    captchaFingerprint(exchange, action, clientId, username);

                            log.info(
                                "[Captcha] PASSED action={} ip={} verifiedKey={}",
                                action, clientIp, verifiedKey
                            );

                            return reactiveRedisTemplate.opsForValue()
                                    .set(replayKey, "1", props.getRateLimit().getFailureWindow())
                                    .then(
                                        reactiveRedisTemplate.opsForValue()
                                            .set(
                                                verifiedKey,
                                                "1",
                                                Duration.ofMinutes(props.getBypassMinutes())
                                            )
                                    )
                                    .then(
                                    	    chainWithOutcome(exchange, chain, resetMode, identifiers)
                                    	        .onErrorResume(ex -> {
                                    	            log.error(
                                    	                "[Captcha] Downstream failure AFTER captcha passed action={} ip={} type={}",
                                    	                action, clientIp, ex.getClass().getSimpleName(), ex
                                    	            );
                                    	            return Mono.error(ex); // propagate
                                    	        })
                                    	);
                        });
            })
            .onErrorResume(MissingCaptchaException.class, ex -> {
                log.warn(
                    "[Captcha] BLOCKED reason=captcha_missing action={} ip={}",
                    action, clientIp
                );
                return captchaForbidden(
                        exchange,
                        "captcha_missing",
                        isTokenEndpoint(exchange.getRequest().getPath().value())
                );
            })
            .onErrorResume(InvalidCaptchaException.class, ex -> {
                log.warn(
                    "[Captcha] BLOCKED reason=captcha_invalid action={} ip={}",
                    action, clientIp
                );
                return captchaForbidden(
                        exchange,
                        "captcha_invalid",
                        isTokenEndpoint(exchange.getRequest().getPath().value())
                );
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
    
    private Mono<Boolean> isCaptchaVerified(ServerWebExchange exchange,
            String action,
            String clientId,
            String username) {
    	
    	String key =
                "captcha:verified:" +
                captchaFingerprint(exchange, action, clientId, username);

        return reactiveRedisTemplate.hasKey(key).onErrorReturn(false);
    }
    
    private String captchaFingerprint(
            ServerWebExchange exchange,
            String action,
            String clientId,
            String username) {
    	String ip = ipUtil.normalizeIp(
                (String) exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP));

        String scheme = exchange.getRequest().getURI().getScheme();
        long minute = Instant.now().getEpochSecond() / 60;

        return DigestUtils.sha256Hex(
                scheme + "|" +
                ip + "|" +
                action + "|" +
                clientId + "|" +
                username + "|" +
                minute
        ).substring(0, 32);
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
    
    private Mono<String> signIdentity(ServerWebExchange exchange, String action) {
        String ip = ipUtil.normalizeIp(
                (String) exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP)
        );
        String scheme = exchange.getRequest().getURI().getScheme();

        CanonicalSecurityIdentity identity =
                new CanonicalSecurityIdentity(
                		scheme,
                        ip,
                        action,
                        exchange.getRequest().getPath().value(),
                        null,null,
                        Instant.now().getEpochSecond() / 60
                );

        try {
            return hmacService.sign(objectMapper.writeValueAsString(identity), "gateway");
        } catch (Exception e) {
            return Mono.error(e);
        }
    }
    
    private Mono<String> signIdentity(
    		ServerWebExchange exchange,
            String ip,
            String action,
            String clientId,
            String username,
            String path
    ) {
    	String scheme = exchange.getRequest().getURI().getScheme();
    	CanonicalSecurityIdentity identity =
            new CanonicalSecurityIdentity(
            	scheme,
                ip,
                action,
                path,
                clientId,
                username,
                Instant.now().getEpochSecond() / 60
            );
    	try {
    		return hmacService.sign(objectMapper.writeValueAsString(identity),"gateway");
    	} catch (Exception e) {
            return Mono.error(e);
        }
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
    
    static class MissingCaptchaException extends RuntimeException {}
    static class InvalidCaptchaException extends RuntimeException {}
}
