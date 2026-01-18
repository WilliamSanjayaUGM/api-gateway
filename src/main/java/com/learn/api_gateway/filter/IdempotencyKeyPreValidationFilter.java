package com.learn.api_gateway.filter;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import com.learn.api_gateway.util.WAFBootstrapUtil;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Newly added
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class IdempotencyKeyPreValidationFilter implements GlobalFilter, Ordered {

    private static final String HEADER = "Idempotency-Key";

    // Short TTL = replay protection, NOT business idempotency
    private static final Duration REPLAY_TTL = Duration.ofSeconds(30);

    // Only protect high-risk endpoints
    private static final List<String> PROTECTED_PATH_PREFIXES = List.of(
            "/payments",
            "/orders",
            "/transfers"
//            ,"/auth"
    );

    private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
    private final WAFBootstrapUtil waf;

    @Override
    public int getOrder() {
        return -720; // AFTER fingerprint/risk, BEFORE rate-limit/captcha
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        ServerHttpRequest req = exchange.getRequest();

        if (!isProtected(req)) {
            return chain.filter(exchange);
        }

        String key = req.getHeaders().getFirst(HEADER);
        
        log.info("-----------IdempotencyKeyPreValidationFilter is running--------");

        if (!isValidKey(key)) {
            log.warn("Missing or invalid Idempotency-Key for {}", req.getPath().value());
            return waf.block(
                    exchange,
                    HttpStatus.BAD_REQUEST,
                    "Missing or invalid Idempotency-Key"
            );
        }

        String clientIp = (String) exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP);
        String redisKey = buildRedisKey(clientIp, key);

        /* ===============================
         * Replay protection (hot-loop)
         * =============================== */
        return reactiveRedisTemplate.opsForValue()
                .setIfAbsent(redisKey, "1", REPLAY_TTL)
                .flatMap(acquired -> {

                    if (Boolean.FALSE.equals(acquired)) {
                        log.warn(
                            "Idempotency replay detected ip={} key={}",
                            clientIp,
                            abbreviate(key)
                        );

                        return waf.block(
                                exchange,
                                HttpStatus.CONFLICT,
                                "Duplicate idempotent request detected"
                        );
                    }

                    return chain.filter(exchange);
                });
    }

    /* ===============================
     * Helpers
     * =============================== */

    private boolean isProtected(ServerHttpRequest req) {
        if (!HttpMethod.POST.equals(req.getMethod())
                && !HttpMethod.PUT.equals(req.getMethod())) {
            return false;
        }

        String path = req.getPath().value();
        return PROTECTED_PATH_PREFIXES.stream().anyMatch(path::startsWith);
    }

    private boolean isValidKey(String key) {
        if (!StringUtils.hasText(key)) return false;

        // UUID v4 preferred (bank-friendly)
        try {
            UUID.fromString(key);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String buildRedisKey(String ip, String key) {
        return "idem:replay:" +
                (ip != null ? ip : "unknown") +
                ":" + key;
    }

    private String abbreviate(String key) {
        return key.length() > 8 ? key.substring(0, 8) + "…" : key;
    }
}
