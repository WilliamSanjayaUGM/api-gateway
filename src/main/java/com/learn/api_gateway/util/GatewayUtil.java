package com.learn.api_gateway.util;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Random;
import java.util.function.Predicate;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

@Slf4j
@Component
public class GatewayUtil {
	private static final String ATTR_CACHED_REQUEST_BODY = "cachedRequestBody";

    private final int warnThreshold;
    private final Predicate<ServerWebExchange> shouldCache;
    private final Random logSampler = new Random();
    
    public GatewayUtil() {
    	this.warnThreshold = 200000; // default warning threshold
        this.shouldCache = exchange -> true;
    }

    public GatewayUtil(
            @Value("${spring.cloud.gateway.cache.warn-threshold:200000}") int warnThreshold // e.g. 200 KB
    ) {
        this(warnThreshold, exchange -> true);
    }

    public GatewayUtil(int warnThreshold, Predicate<ServerWebExchange> shouldCache) {
        this.warnThreshold = warnThreshold;
        this.shouldCache = shouldCache;
    }

    public Mono<ServerWebExchange> cacheRequestBody(ServerWebExchange exchange) {
        if (!shouldCache.test(exchange)) {
            return Mono.just(exchange);
        }

        return DataBufferUtils.join(exchange.getRequest().getBody())
                .timeout(Duration.ofSeconds(10)) // avoid hanging clients
                .retryWhen(Retry.max(1).filter(ex -> ex instanceof IllegalStateException))
                .flatMap(buffer -> {
                    try {
                        int size = buffer.readableByteCount();

                        if (size > warnThreshold && logSampler.nextInt(5) == 0) {
                            String path = exchange.getRequest().getPath().pathWithinApplication().value();
                            log.warn("Large request body detected: {} bytes (> warnThreshold={}) path={}",
                                    size, warnThreshold, path);
                        }

                        byte[] bytes = new byte[size];
                        buffer.read(bytes);
                        DataBufferUtils.release(buffer);

                        DataBufferFactory factory = exchange.getResponse().bufferFactory();

                        ServerHttpRequest decorated = new ServerHttpRequestDecorator(exchange.getRequest()) {
                            @Override
                            public Flux<DataBuffer> getBody() {
                                return Flux.defer(() -> {
                                    DataBuffer copy = factory.wrap(Arrays.copyOf(bytes, bytes.length));
                                    return Flux.just(copy);
                                }).limitRate(32);
                            }
                        };
                        
                        ServerWebExchange mutated = exchange.mutate().request(decorated).build();
                        mutated.getAttributes().put(ATTR_CACHED_REQUEST_BODY, bytes);

                        return Mono.just(mutated);
                    } catch (Exception e) {
                        DataBufferUtils.release(buffer);
                        log.error("Failed to cache request body", e);
                        return Mono.error(new ResponseStatusException(
                                HttpStatus.INTERNAL_SERVER_ERROR,
                                "Failed to cache request body", e));
                    }
                })
                .onErrorResume(e -> {
                    log.error("Failed to cache request body", e);
                    return Mono.error(e);
                });
    }

    public byte[] getCachedRequestBody(ServerWebExchange exchange) {
        return (byte[]) exchange.getAttribute(ATTR_CACHED_REQUEST_BODY);
    }

    public Mono<String> getCachedRequestBodyAsString(ServerWebExchange exchange) {
        byte[] bytes = getCachedRequestBody(exchange);
        return bytes == null
                ? Mono.empty()
                : Mono.just(new String(bytes, StandardCharsets.UTF_8));
    }
}
