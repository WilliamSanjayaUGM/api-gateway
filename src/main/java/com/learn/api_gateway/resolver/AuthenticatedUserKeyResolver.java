package com.learn.api_gateway.resolver;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component("authenticatedUserKeyResolver")
public class AuthenticatedUserKeyResolver implements KeyResolver{

	@Override
	public Mono<String> resolve(ServerWebExchange exchange) {
		String ipHeader = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        String resolvedIp = ipHeader;
        if (resolvedIp == null && exchange.getRequest().getRemoteAddress() != null) {
            resolvedIp = exchange.getRequest().getRemoteAddress().getAddress().getHostAddress();
        }

        final String clientIp = resolvedIp;

        return exchange.getPrincipal()
                .map(p -> clientIp + ":" + p.getName())
                .defaultIfEmpty(clientIp != null ? clientIp : "unknown");
	}

}
