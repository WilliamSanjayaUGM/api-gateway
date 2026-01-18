package com.learn.api_gateway.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.RequiredArgsConstructor;

/**
 * Giving default KeyResolver for all rate-limits where none is explicitly declared.
 */
@Configuration
@RequiredArgsConstructor
public class RateLimiterConfig {
	/**
     * KeyResolver for rate limiting per user IP + authenticated user (if any)
     */
	@Bean
    public KeyResolver defaultKeyResolver(@Qualifier("authenticatedUserKeyResolver") KeyResolver userResolver) {
        return userResolver; // default fallback
    }
}
