package com.learn.api_gateway.config;

import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

import com.learn.api_gateway.service.RedisLeaderLock;

import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class RedisLeaderLockConfig {
	private final ReactiveStringRedisTemplate redisTemplate;
    private final MeterRegistry meterRegistry;
    private final Environment env;

    @Bean
    public RedisLeaderLock redisLeaderLock() {
        String nodeId = UUID.randomUUID().toString();
        return new RedisLeaderLock(
            redisTemplate,
            "leader:lock:jwks-rotation",
            nodeId,
            180L, // TTL seconds (3 minutes)
            meterRegistry,
            env
        );
    }
}
