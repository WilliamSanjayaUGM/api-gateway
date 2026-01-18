package com.learn.api_gateway.util;

import java.time.Duration;
import java.util.Collections;

import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.data.redis.core.script.RedisScript;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Protect against CAPTCHA brute force
 * Signup spam, Bot OTP abuse
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class IpRateLimiter {
	
	private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;

    // Atomic script:
    // INCR key → returns count
    // If first request, set TTL
    private static final String LUA =
            "local c = redis.call('INCR', KEYS[1]); " +
            "if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end; " +
            "return c;";

    public Mono<Boolean> isAllowed(String key, Duration window, int maxRequests) {
        String redisKey = "rate_limit:" + key;
        String ttl = String.valueOf(window.getSeconds());

        RedisScript<Long> script = RedisScript.of(LUA, Long.class);
        
        return reactiveRedisTemplate.execute(
                    script,
                    Collections.singletonList(redisKey),
                    ttl
               )
               .next() // convert Flux<Long> → Mono<Long>
               .map(count -> {
                   log.info("RateLimit {} count={}", key, count);
                   return count <= maxRequests;
               })
               .onErrorResume(ex -> {
                   log.error("RateLimit error for {}: {}", key, ex.getMessage());
                   return Mono.just(false); // fail-closed
               });
    }

    // Optional default accessor
    public Mono<Boolean> isAllowed(String key) {
        return isAllowed(key, Duration.ofMinutes(1), 10);
    }
}
