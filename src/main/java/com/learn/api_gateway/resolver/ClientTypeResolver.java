package com.learn.api_gateway.resolver;

import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

@Component
public class ClientTypeResolver {
	public enum ClientType { BROWSER, MOBILE, API }

    public ClientType resolve(ServerWebExchange exchange) {

        String ua = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.USER_AGENT);

        String clientId = exchange.getRequest()
                .getHeaders()
                .getFirst("X-Client-Id");

        if ("mobile-app".equalsIgnoreCase(clientId) && ua != null
        	    && !ua.contains("Mozilla")) {
        	    return ClientType.MOBILE;
        }

        if (ua != null && ua.contains("Mozilla")) {
            return ClientType.BROWSER;
        }

        return ClientType.API;
    }
}
