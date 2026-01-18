package com.learn.api_gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.learn.api_gateway.util.GatewayUtil;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
@Slf4j
public class RequestBodyCacheFilter implements GlobalFilter, Ordered{
	private final GatewayUtil gatewayUtil;

	@Override
	public int getOrder() {
		return -980;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		ServerHttpRequest req = exchange.getRequest();
		String path = req.getPath().value();
		
		log.info("------------RequestBodyCacheFilter do his job path {}-----------",path);
		
		if (req.getMethod() == HttpMethod.GET || req.getMethod() == HttpMethod.HEAD) {
			return chain.filter(exchange);
		}

		if (!req.getHeaders().containsKey(HttpHeaders.CONTENT_LENGTH) &&
		        !req.getHeaders().containsKey(HttpHeaders.TRANSFER_ENCODING)) {
		    return chain.filter(exchange);
		}
	    if (path.startsWith("/oauth-proxy/") || path.startsWith("/realms/")) {
	        return chain.filter(exchange);
	    }
		return gatewayUtil.cacheRequestBody(exchange)
                .flatMap(chain::filter);
	}
	
}
