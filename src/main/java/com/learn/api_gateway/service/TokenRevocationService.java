package com.learn.api_gateway.service;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.learn.api_gateway.config.properties.RecaptchaConfigProperties;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

@Slf4j
@Service
public class TokenRevocationService {
	
	private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
    private final MeterRegistry meterRegistry;
    private final ObjectMapper objectMapper;
    private final RecaptchaConfigProperties props;
    private final AuditService auditService;

    private static final Duration NEGATIVE_CACHE_TTL = Duration.ofSeconds(30);
    private static final Duration FAILOPEN_GRACE_TTL = Duration.ofSeconds(5);
    private static final String REVOCATION_CHANNEL = "gateway:revocations";
    private static final Duration REDIS_TIMEOUT = Duration.ofMillis(1500);

    private final Counter revokedTokenCounter;
    private final Counter revokedUserCounter;
    private final Counter negativeCacheHitCounter;
    private final Timer publishTimer;
    private final Timer redisSetTimer;
    private final Counter redisErrorCounter;
    private final Counter failOpenCounter;
    
    private final com.github.benmanes.caffeine.cache.Cache<String, Boolean> failOpenCache =
        Caffeine.newBuilder()
            .maximumSize(50_000)
            .expireAfterWrite(FAILOPEN_GRACE_TTL) // NOTE: FAILOPEN_GRACE_TTL should be configurable
            .build();


    public TokenRevocationService(ReactiveRedisTemplate<String, String> reactiveRedisTemplate,
                                  MeterRegistry meterRegistry,
                                  ObjectMapper objectMapper,
                                  RecaptchaConfigProperties props,
                                  AuditService auditService) {
        this.reactiveRedisTemplate = reactiveRedisTemplate;
        this.meterRegistry = meterRegistry;
        this.objectMapper = objectMapper;
        this.props = props;
        this.auditService = auditService;

        this.revokedTokenCounter = Counter.builder("gateway.revocations.token.total")
                .description("Total tokens revoked").register(meterRegistry);
        this.revokedUserCounter = Counter.builder("gateway.revocations.user.total")
                .description("Total user-level revocations").register(meterRegistry);
        this.negativeCacheHitCounter = Counter.builder("gateway.revocations.negcache.hits")
                .description("Negative cache hits for non-revoked tokens").register(meterRegistry);
        this.publishTimer = Timer.builder("gateway.revocations.publish.latency")
                .description("Time to publish revocation event").register(meterRegistry);
        this.redisSetTimer = Timer.builder("gateway.revocations.redis.set.latency")
                .description("Time to set revocation key in redis").register(meterRegistry);
        this.redisErrorCounter = Counter.builder("gateway.revocations.redis.errors")
                .description("Redis errors during revocation ops").register(meterRegistry);
        this.failOpenCounter = Counter.builder("gateway.revocations.failopen.count")
                .description("Fail-open decisions due to transient Redis errors").register(meterRegistry);
    }

    // --- key generation ---
    public static String revokedTokenKey(String rawToken) {
        return "revoked:token:" + DigestUtils.sha256Hex(rawToken);
    }

    public static String revokedUserKey(String userId) {
        return "revoked:user:" + userId;
    }

    // --- token revocation ---
    public Mono<Void> revokeToken(String rawToken, Duration ttl) {
        Objects.requireNonNull(rawToken, "token required");
        Objects.requireNonNull(ttl, "ttl required");

        if (ttl.isZero() || ttl.isNegative()) {
            return Mono.error(new IllegalArgumentException("TTL must be positive: " + ttl));
        }

        Duration ttlWithJitter = addJitter(ttl);
        String key = revokedTokenKey(rawToken);

        log.warn("Revoking token key={} ttl={}s (jittered={}s)", key, ttl.getSeconds(), ttlWithJitter.getSeconds());
        Timer.Sample sample = Timer.start();

        return reactiveRedisTemplate.opsForValue()
                .set(key, "1", ttlWithJitter)
                .doOnSuccess(ok -> sample.stop(redisSetTimer))
                .then(publishRevocationEvent(new RevocationEvent(RevocationEvent.Type.TOKEN, key)))
                .doOnSuccess(v -> {
                    revokedTokenCounter.increment();
                    auditService.auditInfo("TOKEN_REVOKED", null, null,
                            "internal/revoke", "Token revoked", Map.of("key", key));
                })
                .onErrorResume(ex -> handleRedisErrorControlled("revokeToken", key, ex))
                .then();
    }

    public Mono<Void> revokeUser(String userId, Duration ttl) {
        Objects.requireNonNull(userId, "userId required");
        Objects.requireNonNull(ttl, "ttl required");

        if (ttl.isZero() || ttl.isNegative()) {
            return Mono.error(new IllegalArgumentException("TTL must be positive: " + ttl));
        }

        Duration ttlWithJitter = addJitter(ttl);
        String key = revokedUserKey(userId);
        log.info("Revoking all tokens for user={} key={} ttl={}s", userId, key, ttlWithJitter.getSeconds());
        Timer.Sample sample = Timer.start();

        return reactiveRedisTemplate.opsForValue()
                .set(key, "1", ttlWithJitter)
                .doOnSuccess(ok -> sample.stop(redisSetTimer))
                .then(publishRevocationEvent(new RevocationEvent(RevocationEvent.Type.USER, key)))
                .doOnSuccess(v -> {
                    revokedUserCounter.increment();
                    auditService.auditInfo("USER_REVOKED", userId, null,
                            "internal/revoke", "User tokens revoked", Map.of("userId", userId, "key", key));
                })
                .onErrorResume(ex -> handleRedisErrorControlled("revokeUser", key, ex))
                .then();
    }

    // --- check revoked (controlled failover) ---
    public Mono<Boolean> isTokenRevoked(String rawToken, String userId) {
        String userKey = userId == null ? null : revokedUserKey(userId);
        String revokedKey = revokedTokenKey(rawToken);
        String invalidKey = revokedKey + ":invalid";

        // If local failopen exists for any of these, treat as not revoked (short-circuit)
        if (Boolean.TRUE.equals(failOpenCache.getIfPresent(revokedKey + ":failopen"))) {
            return Mono.just(false);
        }
        if (userKey != null && Boolean.TRUE.equals(failOpenCache.getIfPresent(userKey + ":failopen"))) {
            return Mono.just(false);
        }
        if (Boolean.TRUE.equals(failOpenCache.getIfPresent(invalidKey + ":failopen"))) {
            return Mono.just(false);
        }

        // proceed with Redis checks (same as before, but their error handlers will prime local cache)
        List<Mono<Boolean>> checks = new ArrayList<>();
        if (userKey != null) {
            checks.add(reactiveRedisTemplate.hasKey(userKey)
                    .onErrorResume(ex -> handleRedisCheckError("user", userKey, ex)));
        }
        checks.add(reactiveRedisTemplate.hasKey(revokedKey)
                .onErrorResume(ex -> handleRedisCheckError("token", revokedKey, ex)));
        checks.add(reactiveRedisTemplate.hasKey(invalidKey)
                .onErrorResume(ex -> handleRedisCheckError("invalid", invalidKey, ex)));

        return Flux.merge(checks)
                .filter(Boolean::booleanValue)
                .next()
                .map(Boolean::booleanValue)
                .switchIfEmpty(reactiveRedisTemplate.opsForValue()
                        .set(revokedKey + ":negcache", "0", NEGATIVE_CACHE_TTL)
                        .doOnSuccess(v -> negativeCacheHitCounter.increment())
                        .thenReturn(false));
    }

    // --- controlled Redis error handling ---
    private <T> Mono<T> handleRedisErrorControlled(String op, String key, Throwable ex) {
        log.error("Redis error during {} key={} - applying controlled failover", op, key, ex);
        redisErrorCounter.increment();

        if (isFailClosedMode()) {
            log.warn("Fail-closed enforced (secure mode)");
            return Mono.error(new IllegalStateException("Redis unavailable - fail-closed", ex));
        }

        // Fail-open: mark locally and avoid further Redis calls
        log.warn("Fail-open grace mode active - marking local failopen for {}s", FAILOPEN_GRACE_TTL.getSeconds());
        failOpenCounter.increment();
        failOpenCache.put(key + ":failopen", Boolean.TRUE);
        return Mono.empty(); // continue operation (caller must handle empty appropriately)
    }

    private Mono<Boolean> handleRedisCheckError(String keyType, String key, Throwable ex) {
        redisErrorCounter.increment();
        log.error("Redis check error [{} key={}] - applying failover", keyType, key, ex);

        if (isFailClosedMode()) {
            log.warn("Fail-closed mode: treating as revoked");
            return Mono.just(true);
        }

        // If we already have a local marker, honor it
        Boolean marker = failOpenCache.getIfPresent(key + ":failopen");
        if (Boolean.TRUE.equals(marker)) {
            log.debug("Local failopen cache hit for key={}", key);
            failOpenCounter.increment();
            return Mono.just(false);
        }

        // If no local marker, add one and return fail-open decision (not revoked)
        failOpenCache.put(key + ":failopen", Boolean.TRUE);
        failOpenCounter.increment();
        log.warn("Fail-open applied for key={} for {}s", key, FAILOPEN_GRACE_TTL.getSeconds());
        return Mono.just(false);
    }

    private boolean isFailClosedMode() {
        return props.isFailClosedOnRedisError();
    }

    private Duration addJitter(Duration ttl) {
        long seconds = ttl.getSeconds();
        if (seconds <= 1) return ttl;
        int jitter = Math.max(1, (int) (seconds * 0.1));
        int offset = ThreadLocalRandom.current().nextInt(jitter * 2 + 1) - jitter;
        return Duration.ofSeconds(Math.max(1, seconds + offset));
    }

    private Mono<Void> publishRevocationEvent(RevocationEvent e) {
        Timer.Sample sample = Timer.start();
        return Mono.defer(() -> {
            try {
                String payload = objectMapper.writeValueAsString(Map.of(
                        "type", e.getType().name(),
                        "key", e.getKey(),
                        "ts", e.getTs()
                ));
                return reactiveRedisTemplate.convertAndSend(REVOCATION_CHANNEL, payload)
                        .timeout(REDIS_TIMEOUT)
                        .retryWhen(Retry.backoff(3, Duration.ofMillis(200)).maxBackoff(Duration.ofSeconds(3)))
                        .doOnError(err -> {
                            redisErrorCounter.increment();
                            log.warn("Failed to publish revocation event {}", e, err);
                        })
                        .doOnSuccess(sig -> sample.stop(publishTimer))
                        .then();
            } catch (JsonProcessingException ex) {
                log.warn("Error serializing revocation event {}: {}", e, ex.toString());
                return Mono.empty();
            }
        });
    }
    
    public Mono<Boolean> cacheInvalidToken(String rawToken) {
        String key = revokedTokenKey(rawToken) + ":invalid";
        log.debug("Caching invalid token key={} ttl={}s", key, NEGATIVE_CACHE_TTL.getSeconds());

        return reactiveRedisTemplate.opsForValue()
                .set(key, "1", NEGATIVE_CACHE_TTL)
                .thenReturn(Boolean.TRUE)
                .onErrorResume(ex -> {
                    log.warn("Failed to cache invalid token {} due to Redis error: {}", rawToken, ex.toString());
                    return Mono.just(Boolean.TRUE);
                });
    }

    public Mono<Void> revokeTokenAtExpiry(String rawToken, long expiresAtEpochSeconds) {
        Objects.requireNonNull(rawToken, "token required");
        long now = Instant.now().getEpochSecond();
        long ttlSeconds = expiresAtEpochSeconds - now;
        if (ttlSeconds <= 0) {
            log.info("Token already expired, caching as invalid. tokenHash={}", revokedTokenKey(rawToken));
            return cacheInvalidToken(rawToken).then();
        }
        return revokeToken(rawToken, Duration.ofSeconds(ttlSeconds));
    }

    @Data
    public static class RevocationEvent {
        public enum Type { TOKEN, USER }
        private final Type type;
        private final String key;
        private final long ts = Instant.now().getEpochSecond();
    }
}
