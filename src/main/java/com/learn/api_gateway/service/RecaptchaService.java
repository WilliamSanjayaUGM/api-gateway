package com.learn.api_gateway.service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.springframework.data.domain.Range;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.learn.api_gateway.config.properties.RecaptchaConfigProperties;
import com.learn.api_gateway.dto.CaptchaResult;
import com.learn.api_gateway.util.TraceConstants;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class RecaptchaService {
	
	private final ReCaptchaValidator reCaptchaValidator;
    private final RecaptchaConfigProperties props;
    private final MeterRegistry meterRegistry;
    private final Clock clock;
    private final ReactiveStringRedisTemplate reactiveRedisTemplate;

    private Counter globalPassCounter;
    private Counter globalFailCounter;
    private Counter rateLimitBlockCounter;

    private final Cache<String, Counter> endpointPassCounters = Caffeine.newBuilder()
            .maximumSize(100)
            .expireAfterAccess(Duration.ofHours(1))
            .build();

    private final Cache<String, Counter> endpointFailCounters = Caffeine.newBuilder()
            .maximumSize(100)
            .expireAfterAccess(Duration.ofHours(1))
            .build();

    @PostConstruct
    void initMetrics() {
        globalPassCounter = Counter.builder("captcha.validations.pass")
                .description("Total successful reCAPTCHA validations")
                .register(meterRegistry);

        globalFailCounter = Counter.builder("captcha.validations.fail")
                .description("Total failed reCAPTCHA validations")
                .register(meterRegistry);

        rateLimitBlockCounter = Counter.builder("captcha.rate.limit.blocks")
                .description("Requests blocked due to captcha rate limiting")
                .register(meterRegistry);
    }

    public Mono<CaptchaResult> validate(String token,
                                  String clientIp,
                                  String action,
                                  String endpointKey,
                                  ServerWebExchange exchange) {

        ReCaptchaValidator.FailMode failMode = props.getFailMode(endpointKey);
        Duration timeout = props.getTimeouts().getResponse();

        return rateLimitCheck(clientIp, endpointKey)
                .flatMap(allowed -> {
                	log.info("[traceId={}] From RecaptchaService.validate - what is the result of allowed {}",
                    	    Optional.ofNullable(exchange.getAttribute(TraceConstants.TRACE_ID_CONTEXT_KEY)).orElse("N/A"), allowed);
                	
//                    if (!allowed) {
//                        log.warn("[AUDIT] Rate limit exceeded for IP={} endpoint={}", clientIp, endpointKey);
//                        rateLimitBlockCounter.increment(); // 🔹 metric for blocks
//                        recordMetrics(false, endpointKey, exchange);
//                        return Mono.just(false);
//                    }
                    
                    if (!allowed) {
                        log.warn("[CAPTCHA] Rate limited ip={} endpoint={}", clientIp, endpointKey);
                        rateLimitBlockCounter.increment();
                        recordMetrics(false, endpointKey, exchange);
                        return Mono.just(CaptchaResult.RATE_LIMITED);
                    }

//                    return reCaptchaValidator.validate(token, clientIp, action, endpointKey)
//                            .timeout(timeout)
//                            .onErrorResume(ex -> {
//                                log.error("[AUDIT] Redis or validation error for IP={} endpoint={}", clientIp, endpointKey, ex);
//                                meterRegistry.counter("captcha.redis.errors", "endpoint", endpointKey).increment();
//                                return (failMode == ReCaptchaValidator.FailMode.OPEN)
//                                        ? Mono.just(true)
//                                        : Mono.just(false);
//                            })
//                            .doOnError(ex -> log.error("[AUDIT] reCAPTCHA error for IP={} endpoint={}", clientIp, endpointKey, ex))
//                            .onErrorResume(ex -> failMode == ReCaptchaValidator.FailMode.OPEN
//                                    ? Mono.just(true)
//                                    : Mono.just(false))
//                            .doOnNext(success -> recordMetrics(success, endpointKey, exchange));
                
                    return reCaptchaValidator
                            .validate(token, clientIp, action, endpointKey)
                            .timeout(timeout)
                            .map(valid ->
                                    valid
                                            ? CaptchaResult.PASSED
                                            : CaptchaResult.INVALID
                            )
                            .onErrorResume(ex -> {
                                log.error("[CAPTCHA] Provider error endpoint={}", endpointKey, ex);
                                meterRegistry.counter("captcha.provider.errors", "endpoint", endpointKey).increment();

                                return Mono.just(
                                        failMode == ReCaptchaValidator.FailMode.OPEN
                                                ? CaptchaResult.PASSED
                                                : CaptchaResult.PROVIDER_ERROR
                                );
                            })
                            .doOnNext(result ->
                                    recordMetrics(result == CaptchaResult.PASSED, endpointKey, exchange)
                            );
                });
    }

    private void recordMetrics(boolean success, String endpointKey, ServerWebExchange exchange) {
        if (success) globalPassCounter.increment();
        else globalFailCounter.increment();

        Counter endpointCounter = success
                ? endpointPassCounters.get(endpointKey, k ->
                        meterRegistry.counter("captcha.validations.pass", "endpoint", k))
                : endpointFailCounters.get(endpointKey, k ->
                        meterRegistry.counter("captcha.validations.fail", "endpoint", k));

        endpointCounter.increment();

        if (success) CaptchaContext.markPassed(exchange, clock);
    }

    /**
     * Sliding-window rate limit using Redis sorted set (ZSET).
     */
    private Mono<Boolean> rateLimitCheck(String clientIp, String endpointKey) {
        if (!props.isEnableRateLimit()) return Mono.just(true);

        String key = "security:captcha:rl:" + endpointKey + ":" + clientIp;
        long nowMillis = Instant.now(clock).toEpochMilli();
        long windowMillis = props.getRateLimit().getWindowSeconds() * 1000L;
        long minScore = nowMillis - windowMillis;
        long maxAttempts = props.getRateLimit().getMaxFailuresBeforeCaptcha();
        String member = clientIp + ":" + nowMillis;

        var ops = reactiveRedisTemplate.opsForZSet();
        
        return ops.add(key, member, nowMillis)
                .flatMap(added ->                 
                    // remove entries outside the sliding window
                    ops.removeRangeByScore(key, Range.rightOpen(Double.NEGATIVE_INFINITY, (double) minScore))
                )
                .then(ops.size(key))
                .flatMap(count -> 
                    // set TTL on key equal to sliding window to auto-cleanup
                    reactiveRedisTemplate.expire(key, Duration.ofMillis(windowMillis))
                            .thenReturn(count <= maxAttempts)
                )
                .onErrorResume(ex -> {
                    log.error("Rate limit check failed, allowing by default", ex);
                    return Mono.just(true); // fail-open on Redis error
                });
    }

    public static final class CaptchaContext {
        private static final String ATTR_CAPTCHA_PASSED = "captchaPassed";
        private static final String ATTR_CAPTCHA_TIMESTAMP = "captchaTimestamp";

        private CaptchaContext() {}

        static void markPassed(ServerWebExchange exchange, Clock clock) {
            exchange.getAttributes().put(ATTR_CAPTCHA_PASSED, true);
            exchange.getAttributes().put(ATTR_CAPTCHA_TIMESTAMP, Instant.now(clock));
        }

        public static boolean isPassed(ServerWebExchange exchange) {
            return Boolean.TRUE.equals(exchange.getAttribute(ATTR_CAPTCHA_PASSED));
        }

        public static Optional<Instant> getTimestamp(ServerWebExchange exchange) {
            return Optional.ofNullable(exchange.getAttribute(ATTR_CAPTCHA_TIMESTAMP));
        }
    }
}
