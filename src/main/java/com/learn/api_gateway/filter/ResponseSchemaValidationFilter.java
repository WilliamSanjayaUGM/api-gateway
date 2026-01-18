package com.learn.api_gateway.filter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.learn.api_gateway.util.SchemaRegistryLoader;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.ValidationMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

/**
 * response JSON validation
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class ResponseSchemaValidationFilter implements GlobalFilter, Ordered {

    private final ObjectMapper objectMapper;
    private final SchemaRegistryLoader schemaRegistryLoader;

    @Value("${schema.enabled:true}")
    private boolean schemaValidationEnabled;

    @Value("${schema.response.enabled:false}")
    private boolean responseValidationEnabled;

    @Value("${schema.response.max-body-size-bytes:2000000}")
    private int maxBodySizeBytes;

    @Value("${schema.response.max-depth:50}")
    private int maxDepth;

    @Value("${schema.response.fail-on-error:false}")
    private boolean failOnError;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        if (!schemaValidationEnabled || !responseValidationEnabled) {
            return chain.filter(exchange);
        }

        String path = (String) exchange.getAttributes().getOrDefault("schema.path",
                exchange.getRequest().getURI().getPath());
        String version = (String) exchange.getAttributes().getOrDefault("schema.version", null);

        JsonSchema schema = schemaRegistryLoader.findResponseSchema(path, version);
        if (schema == null) {
            return chain.filter(exchange); // no response schema → skip
        }

        ServerHttpResponse response = exchange.getResponse();

        MediaType ct = response.getHeaders().getContentType();
        if (ct != null && !MediaType.APPLICATION_JSON.isCompatibleWith(ct)) {
            return chain.filter(exchange); // only validate JSON responses
        }

        ServerHttpResponseDecorator decorated = new ServerHttpResponseDecorator(response) {
            @Override
            public Mono<Void> writeWith(org.reactivestreams.Publisher<? extends DataBuffer> body) {
                if (!(body instanceof Flux)) {
                    return super.writeWith(body);
                }

                Flux<DataBuffer> flux = (Flux<DataBuffer>) body;
                AtomicLong totalBytes = new AtomicLong(0);

                return DataBufferUtils.join(
                                flux.takeUntil(buffer -> {
                                    long size = totalBytes.addAndGet(buffer.readableByteCount());
                                    if (size > maxBodySizeBytes) {
                                        log.warn("Response body exceeds max size {} bytes – skipping schema validation",
                                                maxBodySizeBytes);
                                        return true;
                                    }
                                    return false;
                                }))
                        .flatMap(buffer -> {
                            byte[] bytes = new byte[buffer.readableByteCount()];
                            buffer.read(bytes);
                            DataBufferUtils.release(buffer);

                            try {
                                JsonNode json = objectMapper.readTree(bytes);
                                enforceMaxDepth(json, maxDepth);

                                Set<ValidationMessage> errors = schema.validate(json);
                                if (!errors.isEmpty()) {
                                    log.warn("Response schema validation FAILED on {} v{}: {}",
                                            path, version, errors);

                                    if (failOnError) {
                                        getDelegate().setStatusCode(org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR);
                                        byte[] errBytes = "Response schema validation failed".getBytes(StandardCharsets.UTF_8);
                                        DataBuffer errBuf = bufferFactory().wrap(errBytes);
                                        return super.writeWith(Mono.just(errBuf));
                                    }
                                } else {
                                    log.debug("Response schema validation OK for {} v{}", path, version);
                                }

                                // write original body back
                                DataBuffer newBuf = bufferFactory().wrap(bytes);
                                return super.writeWith(Mono.just(newBuf));

                            } catch (Exception e) {
                                log.error("Failed to validate response JSON for {} v{}", path, version, e);
                                if (failOnError) {
                                    getDelegate().setStatusCode(org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR);
                                    byte[] errBytes = "Response validation error".getBytes(StandardCharsets.UTF_8);
                                    DataBuffer errBuf = bufferFactory().wrap(errBytes);
                                    return super.writeWith(Mono.just(errBuf));
                                }
                                // log-only, then send original
                                DataBuffer newBuf = bufferFactory().wrap(bytes);
                                return super.writeWith(Mono.just(newBuf));
                            }
                        });
            }
        };

        return chain.filter(exchange.mutate().response(decorated).build());
    }

    private void enforceMaxDepth(JsonNode node, int maxDepth) {
        checkDepth(node, 0, maxDepth);
    }

    private void checkDepth(JsonNode node, int depth, int maxDepth) {
        if (depth > maxDepth) {
            throw new IllegalArgumentException("JSON nesting too deep");
        }
        if (node.isContainerNode()) {
            node.elements().forEachRemaining(child -> checkDepth(child, depth + 1, maxDepth));
        }
    }

    @Override
    public int getOrder() {
        return 5; // after routing & business filters, but before logging-out if you like
    }
}
