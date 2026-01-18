package com.learn.api_gateway.resolver;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.learn.api_gateway.filter.ClientIpFilter;

import reactor.core.publisher.Mono;

@Primary
@Component("userIpKeyResolver")
public class UserIpKeyResolver implements KeyResolver{

	@Override
	public Mono<String> resolve(ServerWebExchange exchange) {
//		String clientIp = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
//        if (clientIp == null && exchange.getRequest().getRemoteAddress() != null) {
//            clientIp = exchange.getRequest().getRemoteAddress().getAddress().getHostAddress();
//        }
//        return Mono.justOrEmpty(clientIp != null ? clientIp : "unknown");
        
        String clientIp = exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP);

        if (clientIp == null || "unknown".equals(clientIp)) {
            return Mono.empty(); // fail closed
        }

        return Mono.just(clientIp);
	}

}
