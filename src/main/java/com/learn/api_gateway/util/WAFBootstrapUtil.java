package com.learn.api_gateway.util;

import java.nio.charset.StandardCharsets;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class WAFBootstrapUtil {
	public static final String ATTR_WAF_BLOCKED = "waf.blocked";
	
	public boolean isBootstrapPath(ServerWebExchange exchange) {
	    String path = exchange.getRequest().getURI().getPath();
	    return path.startsWith("/oauth-proxy/")
	        || path.startsWith("/realms/")
	        || path.startsWith("/actuator/")
	        || path.startsWith("/captcha/");
	}
	
	public Mono<Void> block(ServerWebExchange exchange,HttpStatus status,String reason) {
		exchange.getAttributes().put(ATTR_WAF_BLOCKED, true);
		
		ServerHttpResponse response = exchange.getResponse();
		if (response.isCommitted()) {
	        return Mono.empty(); // 🔥 REQUIRED
	    }
		
		response.setStatusCode(status);
		response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
		
		byte[] body = """
		{
		"error": "Request blocked by security policy",
		"reason": "%s",
		"path": "%s"
		}
		""".formatted(reason, exchange.getRequest().getPath().value())
		.getBytes(StandardCharsets.UTF_8);
		
		return response.writeWith(Mono.just(response.bufferFactory().wrap(body))).then(Mono.empty());
	}
}
