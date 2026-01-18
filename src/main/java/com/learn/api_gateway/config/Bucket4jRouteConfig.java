package com.learn.api_gateway.config;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;

import com.learn.api_gateway.util.IpRateLimiter;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * This custom non-Bucket4J logic is still necessary because:
 * /auth/login → max 5 requests per minute per IP
 * Which is NOT part of YAML Bucket4j rules.
 * Right now it's not being used anymore because the login is using keycloak redirect page
 */
//@Configuration
//@Slf4j
//public class Bucket4jRouteConfig {
//
//    private final IpRateLimiter ipRateLimiter;
//    private final KeyResolver ipKeyResolver;
//
//    @Autowired
//    public Bucket4jRouteConfig(
//            IpRateLimiter ipRateLimiter,
//            @Qualifier("userIpKeyResolver") KeyResolver ipKeyResolver) {
//        this.ipRateLimiter = ipRateLimiter;
//        this.ipKeyResolver = ipKeyResolver;
//    }
//
//    @Bean
//    public RouteLocator bucket4jRoutes(RouteLocatorBuilder builder) {
//        return builder.routes()
//
//            // --- SPECIAL RATE LIMIT FOR /auth/login
//            .route("auth-login", r -> r
//                .path("/auth/login")
//                .filters(f -> f.filter((exchange, chain) ->
//                    Mono.defer(() -> ipKeyResolver.resolve(exchange))
//                        .flatMap(ip -> ipRateLimiter.isAllowed(ip, Duration.ofMinutes(1), 5))
//                        .flatMap(allowed -> {
//                        	log.info("----------Bucket4jRouteConfig RouteLocator------------");
//                            if (!allowed) {
//                                exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
//                                return exchange.getResponse().setComplete();
//                            }
//                            return chain.filter(exchange);
//                      })
//                ))
//                .uri("lb://auth-service")
//            )
//
//            .build();
//    }
//}

