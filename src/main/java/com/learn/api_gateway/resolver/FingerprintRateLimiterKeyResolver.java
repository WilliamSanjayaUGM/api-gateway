package com.learn.api_gateway.resolver;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component("fingerprintRateLimiterKeyResolver")
@RequiredArgsConstructor
public class FingerprintRateLimiterKeyResolver implements KeyResolver {

    public static final String ATTR_FINGERPRINT = "security.clientFingerprint";

    // Fallback resolution chain
    private final @Qualifier("authenticatedUserKeyResolver") KeyResolver userResolver;
    private final @Qualifier("userIpKeyResolver") KeyResolver ipResolver;

    @Override
    public Mono<String> resolve(ServerWebExchange exchange) {

        // Highest priority → fingerprint
        final String fingerprint = exchange.getAttribute(ATTR_FINGERPRINT);
        if (fingerprint != null) {
            return Mono.just("fp:" + fingerprint);
        }

        // Second priority → authenticated user (userId + IP)
        return userResolver.resolve(exchange)
                .map(key -> "auth:" + key)
                .flatMap(authKey -> Mono.just(authKey))
                .switchIfEmpty(
                        // Final fallback → raw IP
                        ipResolver.resolve(exchange)
                                .map(ip -> "ip:" + ip)
                );
    }
}
