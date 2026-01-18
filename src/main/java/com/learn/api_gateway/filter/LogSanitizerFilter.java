package com.learn.api_gateway.filter;

import java.util.regex.Pattern;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
/**
 * This one is for data sanitization, Sanitize sensitive attributes
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@Slf4j
public class LogSanitizerFilter implements WebFilter{
	private static final Pattern SECRET_PATTERN = Pattern.compile("(client_secret=)([^&\\s]+)");
	
	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		exchange.getAttributes().replaceAll((k, v) ->
        	v instanceof String ? SECRET_PATTERN.matcher((String) v).replaceAll("$1****") : v);
		log.info("------------LogSanitizerFilter is passed--------");
		return chain.filter(exchange);
	}

}
