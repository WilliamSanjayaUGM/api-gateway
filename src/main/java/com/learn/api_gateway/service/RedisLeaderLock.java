package com.learn.api_gateway.service;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;

import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Handles the low-level Redis lock operations.
 */
@Slf4j
@RequiredArgsConstructor
public class RedisLeaderLock {
	private final ReactiveStringRedisTemplate reactiveRedisTemplate;
    private final String lockKey;
    private final String nodeId;
    private final long ttlSeconds;
    private final MeterRegistry meterRegistry;
    private final Environment env;

    private static final String RENEW_SCRIPT = """
        local val = redis.call("get", KEYS[1])
        if val and string.sub(val, 1, string.len(ARGV[1])) == ARGV[1] then
            redis.call("setex", KEYS[1], tonumber(ARGV[2]), ARGV[1] .. ":" .. ARGV[3])
            return 1
        else
            return 0
        end
        """;

    private static final String RELEASE_SCRIPT = """
        local val = redis.call("get", KEYS[1])
        if val and string.sub(val, 1, string.len(ARGV[1])) == ARGV[1] then
            redis.call("del", KEYS[1])
            return 1
        else
            return 0
        end
        """;

    private final Counter leaderAcquiredCounter;
    private final Counter leaderLostCounter;

    public RedisLeaderLock(ReactiveStringRedisTemplate reactiveRedisTemplate,
                           String lockKey,
                           String nodeId,
                           long ttlSeconds,
                           MeterRegistry meterRegistry,
                           Environment env) {

        this.reactiveRedisTemplate = Objects.requireNonNull(reactiveRedisTemplate);
        this.lockKey = Objects.requireNonNull(lockKey);
        this.nodeId = Objects.requireNonNull(nodeId);
        this.ttlSeconds = ttlSeconds;
        this.meterRegistry = Objects.requireNonNull(meterRegistry);
        this.env = Objects.requireNonNull(env);

        this.leaderAcquiredCounter = Counter.builder("leader_acquired_total")
                .tag("lockKey", lockKey)
                .register(meterRegistry);

        this.leaderLostCounter = Counter.builder("leader_lost_total")
                .tag("lockKey", lockKey)
                .register(meterRegistry);
    }

    public String getNodeId() {
        return nodeId;
    }

    /** Acquire the lock if not held by anyone */
    public Mono<Boolean> acquire() {
        String value = nodeId + ":" + System.currentTimeMillis();

        return reactiveRedisTemplate.opsForValue()
                .setIfAbsent(lockKey, value, Duration.ofSeconds(ttlSeconds))
                .defaultIfEmpty(false)
                .doOnNext(acquired -> {
                    if (acquired) {
                        leaderAcquiredCounter.increment();
                        logAtEnv("Node {} acquired leadership for {}", nodeId, lockKey);
                    }
                });
    }

    /** Check if current node owns the lock */
    public Mono<Boolean> isOwner() {
        return reactiveRedisTemplate.opsForValue()
                .get(lockKey)
                .map(val -> val != null && val.startsWith(nodeId + ":"))
                .defaultIfEmpty(false);
    }

    /** Renew the lock atomically only if current node owns it */
    public Mono<Boolean> renew() {
        DefaultRedisScript<Long> script = new DefaultRedisScript<>();
        script.setScriptText(RENEW_SCRIPT);
        script.setResultType(Long.class);

        String newVersion = String.valueOf(System.currentTimeMillis());

        return reactiveRedisTemplate.execute(
                        script,
                        Collections.singletonList(lockKey),
                        nodeId,
                        String.valueOf(ttlSeconds),
                        newVersion
                )
                .next()
                .map(result -> result != null && result == 1)
                .defaultIfEmpty(false)
                .doOnNext(renewed -> {
                    if (renewed) {
                        logAtEnv("Node {} renewed leadership on {}", nodeId, lockKey);
                    } else {
                        leaderLostCounter.increment();
                        log.warn("Node {} lost leadership on {}", nodeId, lockKey);
                    }
                });
    }

    /** Release the lock atomically only if current node owns it */
    public Mono<Void> release() {
        DefaultRedisScript<Long> script = new DefaultRedisScript<>();
        script.setScriptText(RELEASE_SCRIPT);
        script.setResultType(Long.class);

        return reactiveRedisTemplate.execute(
                        script,
                        Collections.singletonList(lockKey),
                        nodeId
                )
                .next()
                .doOnNext(result -> {
                    if (result != null && result == 1) {
                        leaderLostCounter.increment();
                        logAtEnv("Node {} released leadership on {}", nodeId, lockKey);
                    }
                })
                .onErrorResume(e -> {
                    log.error("Failed to release Redis leader lock: {}", e.getMessage(), e);
                    return Mono.empty();
                })
                .then();
    }

    private void logAtEnv(String msg, Object... args) {
        if (Arrays.asList(env.getActiveProfiles()).contains("prod")) {
            log.info(msg, args);
        } else {
            log.debug(msg, args);
        }
    }
}
