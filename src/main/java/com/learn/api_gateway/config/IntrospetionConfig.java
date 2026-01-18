package com.learn.api_gateway.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveRedisTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.learn.api_gateway.config.properties.OpaqueTokenProperties;
import com.learn.api_gateway.config.properties.SecurityCacheProperties;
import com.learn.api_gateway.introspector.CachingRevocationAwareIntrospector;
import com.learn.api_gateway.service.TokenRevocationService;

import lombok.extern.slf4j.Slf4j;

/**
 * The brain of token validation.
 */
@Configuration
@Slf4j
public class IntrospetionConfig {
	@Bean
    public CachingRevocationAwareIntrospector cachingRevocationAwareIntrospector(
    		@Qualifier("reactiveByteRedisTemplate") ReactiveRedisTemplate<String, byte[]> principalCache,
            TokenRevocationService tokenRevocationService,
            SecurityCacheProperties cacheProps,
            OpaqueTokenProperties opaqueProps,
            ObjectMapper objectMapper
    ) {
        log.info("Initializing CachingRevocationAwareIntrospector with URI: {}", opaqueProps.getOauth2().getOpaqueToken().getIntrospectionUri());

        CachingRevocationAwareIntrospector introspector =
                new CachingRevocationAwareIntrospector(
                		opaqueProps.getOauth2().getOpaqueToken().getIntrospectionUri(),
                		opaqueProps.getOauth2().getOpaqueToken().getClientId(),
                		opaqueProps.getOauth2().getOpaqueToken().getClientSecret(),
                        principalCache,
                        tokenRevocationService,
                        cacheProps,
                        opaqueProps,
                        objectMapper
                );

        // Enable JWS and key rotation awareness only for production
        String activeProfile = System.getProperty("spring.profiles.active", "dev");
        boolean prod = "prod".equalsIgnoreCase(activeProfile);

        introspector.enableJwsSignatureValidation(prod);
        introspector.enableKeyRotationAwareness(prod);
        introspector.setJwksUri(opaqueProps.getOauth2().getResourceserver().getJwkPublicKeyUri());

        return introspector;
    }
}
