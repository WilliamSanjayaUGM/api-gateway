package com.learn.api_gateway.filter;

import java.util.Iterator;
import java.util.Map;

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

/**
 * Notes: newly added
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class JsonStructureAbuseFilter implements GlobalFilter, Ordered {

    private static final int MAX_DEPTH = 40;
    private static final int MAX_KEYS = 10_000;
    private static final int MAX_ARRAY_ELEMENTS = 10_000;
    private static final int MAX_STRING_LENGTH = 100_000; // 100 KB

    private final ObjectMapper objectMapper;
    private final WAFBootstrapUtil wafBootstrapUtil;
    private final GatewayUtil gatewayUtil;
    
    @Override
	public int getOrder() {
		return -655;
	}

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        // Bypass bootstrap endpoints
        if (wafBootstrapUtil.isBootstrapPath(exchange)) {
            return chain.filter(exchange);
        }
        
        log.info("---------JsonStructureAbuseFilter is running --------------");

        MediaType ct = exchange.getRequest().getHeaders().getContentType();
        if (ct == null || !MediaType.APPLICATION_JSON.isCompatibleWith(ct)) {
            return chain.filter(exchange);
        }
        
        byte[] body = gatewayUtil.getCachedRequestBody(exchange);
        if (body == null || body.length == 0) {
            return chain.filter(exchange);
        }

        try {
            JsonNode root = objectMapper.readTree(body);

            validateNode(root, 0, new Counter());

        } catch (IllegalStateException ex) {
            log.warn("JSON structure abuse detected: {}", ex.getMessage());
            return wafBootstrapUtil.block(
                    exchange,
                    HttpStatus.BAD_REQUEST,
                    "Malformed or abusive JSON payload"
            );
        } catch (Exception ex) {
            log.warn("Invalid JSON payload", ex);
            return wafBootstrapUtil.block(
                    exchange,
                    HttpStatus.BAD_REQUEST,
                    "Invalid JSON payload"
            );
        }

        return chain.filter(exchange);
    }

    /* =====================================================
     * RECURSIVE VALIDATION (SAFE & BOUNDED)
     * ===================================================== */
    private void validateNode(
            JsonNode node,
            int depth,
            Counter counter) {

        if (depth > MAX_DEPTH) {
            throw new IllegalStateException("JSON nesting depth exceeded");
        }

        if (node.isValueNode()) {
            if (node.isTextual() && node.textValue().length() > MAX_STRING_LENGTH) {
                throw new IllegalStateException("JSON string too large");
            }
            return;
        }

        if (node.isArray()) {
            if (node.size() > MAX_ARRAY_ELEMENTS) {
                throw new IllegalStateException("JSON array too large");
            }
            for (JsonNode element : node) {
                validateNode(element, depth + 1, counter);
            }
            return;
        }

        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                counter.increment();
                if (counter.value() > MAX_KEYS) {
                    throw new IllegalStateException("Too many JSON keys");
                }
                Map.Entry<String, JsonNode> entry = fields.next();
                validateNode(entry.getValue(), depth + 1, counter);
            }
        }
    }

    /* =====================================================
     * COUNTER (avoids Atomic overhead)
     * ===================================================== */
    static final class Counter {
        private int count = 0;
        void increment() { count++; }
        int value() { return count; }
    }
}
