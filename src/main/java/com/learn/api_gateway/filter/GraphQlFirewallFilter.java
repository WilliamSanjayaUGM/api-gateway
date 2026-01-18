package com.learn.api_gateway.filter;

import java.nio.charset.StandardCharsets;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.learn.api_gateway.util.GatewayUtil;
import com.learn.api_gateway.util.WAFBootstrapUtil;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Component
@Slf4j
@RequiredArgsConstructor
public class GraphQlFirewallFilter implements GlobalFilter, Ordered {

    private static final int MAX_DEPTH = 15;
    private static final int MAX_LENGTH = 10_000;
    private static final int MAX_BATCH = 20;

    private final ObjectMapper mapper;
    private final WAFBootstrapUtil wafBootStrapUtil;
    private final GatewayUtil gatewayUtil;
    
    @Override
	public int getOrder() {
		return -760;
	}

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    	if (wafBootStrapUtil.isBootstrapPath(exchange)) {
            return chain.filter(exchange);
        }
    	
        MediaType ct = exchange.getRequest().getHeaders().getContentType();
        if (ct == null) return chain.filter(exchange);

        boolean candidate = ct.toString().contains("graphql") ||
                            ct.isCompatibleWith(MediaType.APPLICATION_JSON);
        
        log.info("-------GraphQlFirewallFilter is candidate {}-------", candidate);
        
        if (!candidate) {
        	return chain.filter(exchange);
        }
        
        byte[] body = gatewayUtil.getCachedRequestBody(exchange);
        if (body == null || body.length == 0) {
            return chain.filter(exchange);
        }

        String payload = new String(body, StandardCharsets.UTF_8);
        if (looksLikeGraphQl(payload) && isGraphQlAbusive(payload)) {
            return wafBootStrapUtil.block(
                exchange,
                HttpStatus.BAD_REQUEST,
                "GraphQL attack blocked"
            );
        }

        return chain.filter(exchange);
    }

    private boolean looksLikeGraphQl(String body) {
        try {
            JsonNode root = mapper.readTree(body);
            if (root.isObject()) return root.has("query");
            if (root.isArray()) return root.get(0).has("query");
        } catch (Exception ignore) {}
        return false;
    }

    private boolean isGraphQlAbusive(String body) {

        try {
            JsonNode root = mapper.readTree(body);
            if (root.isArray()) {
                if (root.size() > MAX_BATCH) return true;
                for (JsonNode node : root)
                    if (isSingleQueryAbusive(node.get("query").asText())) return true;
                return false;
            }
            return isSingleQueryAbusive(root.get("query").asText());
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isSingleQueryAbusive(String q) {

        if (q.length() > MAX_LENGTH) return true;

        int depth = 0;
        int max = 0;

        for (char c : q.toCharArray()) {
            if (c == '{') max = Math.max(max, ++depth);
            if (c == '}') depth--;
            if (max > MAX_DEPTH) return true;
        }

        if (q.chars().filter(ch -> ch == '.').count() > 100) return true;
        if (q.chars().filter(ch -> ch == '@').count() > 50) return true;

        return false;
    }
}
