package com.learn.api_gateway.filter;

import java.nio.charset.StandardCharsets;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebInputException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.learn.api_gateway.util.GatewayUtil;
import com.learn.api_gateway.util.SchemaRegistryLoader;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.ValidationMessage;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * request validator + version negotiation
 */
//@Component
//@RequiredArgsConstructor
//@Slf4j
//public class ApiSchemaValidationFilter implements GlobalFilter, Ordered {
//	
//	private final ObjectMapper objectMapper;
//    private final SchemaRegistryLoader schemaRegistryLoader;
//    private final GatewayUtil gatewayUtil;
//
//    @Value("${schema.enabled:true}")
//    private boolean schemaValidationEnabled;
//
//    @Value("${schema.version-header:X-Schema-Version}")
//    private String versionHeaderName;
//
//    @Value("${schema.default-version:v1}")
//    private String defaultVersion;
//
//    @Value("${schema.request.max-body-size-bytes:2000000}")
//    private int maxBodySizeBytes;
//
//    @Value("${schema.request.max-depth:50}")
//    private int maxDepth;
//
//    @Override
//    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
//
//        if (!schemaValidationEnabled) {
//            return chain.filter(exchange);
//        }
//
//        ServerHttpRequest request = exchange.getRequest();
//        String path = request.getURI().getPath();
//
//        // Only validate POST, PUT, PATCH
//        HttpMethod method = request.getMethod();
//        if (!(HttpMethod.POST.equals(method) ||
//              HttpMethod.PUT.equals(method) ||
//              HttpMethod.PATCH.equals(method))) {
//            return chain.filter(exchange);
//        }
//
//        // Skip excluded paths (from schema.excluded-paths)
//        Set<String> excluded = schemaRegistryLoader.getExcludedPaths();
//        if (excluded.stream().anyMatch(path::startsWith)) {
//            return chain.filter(exchange);
//        }
//
//        // Content-Type must be JSON
//        MediaType contentType = request.getHeaders().getContentType();
//        if (contentType == null || !MediaType.APPLICATION_JSON.isCompatibleWith(contentType)) {
//            return badRequest(exchange, "Content-Type application/json is required");
//        }
//
//        // Version negotiation from header
//        String rawVersion = request.getHeaders().getFirst(versionHeaderName);
//        final String version = (rawVersion == null || rawVersion.isBlank())
//                ? defaultVersion
//                : rawVersion.trim().toLowerCase();
//
//        JsonSchema schema = schemaRegistryLoader.findRequestSchema(path, version);
//        if (schema == null) {
//            // No schema for this path+version → skip (by design)
//            return chain.filter(exchange);
//        }
//        
//        byte[] bodyBytes = gatewayUtil.getCachedRequestBody(exchange);
//        if (bodyBytes == null || bodyBytes.length == 0) {
//        	return badRequest(exchange, "Request body must not be empty");
//        }
//        
//        if (bodyBytes.length > maxBodySizeBytes) {
//            return badRequest(exchange, "Request body too large");
//        }
//        
//        try {
//            JsonNode jsonNode = objectMapper.readTree(bodyBytes);
//            enforceMaxDepth(jsonNode, maxDepth);
//
//            Set<ValidationMessage> errors = schema.validate(jsonNode);
//            if (!errors.isEmpty()) {
//                log.warn("Schema validation failed path={} v={}", path, version);
//                return badRequest(exchange, errors.toString());
//            }
//            
//            exchange.getAttributes().put("schema.version", version);
//            exchange.getAttributes().put("schema.path", path);
//
//            return chain.filter(exchange);
//        } catch (Exception ex) {
//            return badRequest(exchange, "Malformed or invalid JSON");
//        }
//    }
//
//    private void enforceMaxDepth(JsonNode node, int maxDepth) {
//        checkDepth(node, 0, maxDepth);
//    }
//
//    private void checkDepth(JsonNode node, int depth, int maxDepth) {
//        if (depth > maxDepth) {
//            throw new ServerWebInputException("JSON nesting too deep");
//        }
//        if (node.isContainerNode()) {
//            node.elements().forEachRemaining(child -> checkDepth(child, depth + 1, maxDepth));
//        }
//    }
//
//    private Mono<Void> badRequest(ServerWebExchange exchange, String message) {
//        exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);
//        DataBuffer buffer = exchange.getResponse().bufferFactory()
//                .wrap(message.getBytes(StandardCharsets.UTF_8));
//        return exchange.getResponse().writeWith(Mono.just(buffer));
//    }
//
//    @Override
//    public int getOrder() {
//        return -740; // Before OpaqueTokenFilter & RewritePath
//    }
//}
