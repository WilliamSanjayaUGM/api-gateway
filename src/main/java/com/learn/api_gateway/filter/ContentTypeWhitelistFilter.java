package com.learn.api_gateway.filter;

import java.util.Set;

import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import com.learn.api_gateway.util.WAFBootstrapUtil;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Blocks unwanted types like text/html, application/javascript, multipart/form-data, etc.
 */
@Component
@Slf4j
@Order(-790)
public class ContentTypeWhitelistFilter implements WebFilter {
	
	private final WAFBootstrapUtil wafBootStrapUtil;
	
	public ContentTypeWhitelistFilter(WAFBootstrapUtil wafBootStrapUtil) {
		this.wafBootStrapUtil=wafBootStrapUtil;
	}
	
    private static final Set<MediaType> ALLOWED_TYPES = Set.of(
            MediaType.APPLICATION_JSON,
            MediaType.APPLICATION_FORM_URLENCODED
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    	
    	if (wafBootStrapUtil.isBootstrapPath(exchange)) {
    		log.info("-----------ContentTypeWhitelistFilter bypassed WAF -------------");
            return chain.filter(exchange);
        }
    	
        MediaType type = exchange.getRequest().getHeaders().getContentType();
        
        if (type != null && ALLOWED_TYPES.stream().noneMatch(type::isCompatibleWith)) {
            log.info("Blocked unsupported Content-Type: {}", type);
//            exchange.getResponse().setStatusCode(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
//            return exchange.getResponse().setComplete();
            
            return wafBootStrapUtil.block(
                    exchange,
                    HttpStatus.UNSUPPORTED_MEDIA_TYPE,
                    "Unsupported Content-Type: " + type
            );
        }
        
        log.info("-------Passed ContentTypeWhitelistFilter-------", type);
        return chain.filter(exchange);
    }

}

