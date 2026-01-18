package com.learn.api_gateway.filter;

import java.security.MessageDigest;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.zip.CRC32C;

import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.learn.api_gateway.config.properties.GatewayCacheProperties;
import com.learn.api_gateway.util.ErrorResponseWriter;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * HTTP VALIDATION CACHE (client/CDN-side),(ETag/304) for bandwidth optimization
 */
@Component
@Slf4j
public class CacheResponseGlobalFilter implements GlobalFilter, Ordered {

	private final GatewayCacheProperties props;
    private final ErrorResponseWriter errorResponseWriter;

    private static final List<Pattern> CACHEABLE_PATHS = List.of(
            Pattern.compile("^/product-detail/.*"),
            Pattern.compile("^/product-detail/static/.*"),
            Pattern.compile("^/public/.*"),
            Pattern.compile("^/assets/.*")
    );

    public CacheResponseGlobalFilter(GatewayCacheProperties props,
                                     ErrorResponseWriter errorResponseWriter) {
        this.props = props;
        this.errorResponseWriter = errorResponseWriter;
    }

    @Override
    public int getOrder() {
        return -2; // after routing, before write
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String path = exchange.getRequest().getPath().value();

        // 1. Path allow-list
        boolean allowed = CACHEABLE_PATHS.stream()
                .anyMatch(p -> p.matcher(path).matches());

        if (!allowed) {
            return chain.filter(exchange);
        }

        // 2. GET only
        if (!HttpMethod.GET.equals(exchange.getRequest().getMethod())) {
            return chain.filter(exchange);
        }

        // 3. Never cache authenticated content
        if (exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            return chain.filter(exchange);
        }
        // 3b. Never cache session-based content
        if (exchange.getRequest().getHeaders().containsKey(HttpHeaders.COOKIE)) {
            return chain.filter(exchange);
        }

        ServerHttpResponse originalResponse = exchange.getResponse();
        HttpHeaders headers = originalResponse.getHeaders();

        // 4. Cache-Control
        headers.remove(HttpHeaders.PRAGMA);
        
        headers.set(HttpHeaders.CACHE_CONTROL,
                props.getCacheControl() != null
                        ? props.getCacheControl()
                        : "public, max-age=" + props.getDefaultTtl());

        log.info("------value props.getDefaultTtl: {}", props.getDefaultTtl());

        // 5. Last-Modified
        if (props.isLastModifiedEnabled() && !headers.containsKey(HttpHeaders.LAST_MODIFIED)) {
            headers.set(HttpHeaders.LAST_MODIFIED,
                    ZonedDateTime.now(ZoneOffset.UTC)
                            .truncatedTo(ChronoUnit.SECONDS)
                            .format(DateTimeFormatter.RFC_1123_DATE_TIME));
        }

        // 6. Skip if backend already set ETag
        if (headers.getETag() != null) {
            return chain.filter(exchange);
        }
        
        // 7. Decorate response safely
        ServerHttpResponseDecorator decorated = new ServerHttpResponseDecorator(originalResponse) {

            @Override
            @SuppressWarnings("unchecked")
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                if (!(body instanceof Flux)) {
                    return super.writeWith(body);
                }
                
                Flux<DataBuffer> flux = (Flux<DataBuffer>) body;

                return DataBufferUtils.join(flux)
                        .flatMap(buffer -> {
                            byte[] bytes = new byte[buffer.readableByteCount()];
                            buffer.read(bytes);
                            DataBufferUtils.release(buffer);

                            long size = bytes.length;
                            long max = props.getMaxEtagBodySize();

                            if (size == 0 || size > max) {
                                log.info("ETag skipped (size={})", size);
                                // just forward the body as-is
                                return super.writeWith(Mono.just(bufferFactory().wrap(bytes)));
                            }
                            
                            if (getStatusCode() != null && getStatusCode().isError()) {
                                return super.writeWith(Mono.just(bufferFactory().wrap(bytes)));
                            }

                            try {
                                String etag = computeEtag(bytes);
                                HttpHeaders h = getDelegate().getHeaders();
                                
                                if (!h.containsKey(HttpHeaders.ETAG)) {
                                    h.set(HttpHeaders.ETAG, etag);
                                    log.info("ETag applied: {}", etag);
                                }
                                //RFC 9110 COMPLIANT
                                String inm = exchange.getRequest()
                                        .getHeaders()
                                        .getFirst(HttpHeaders.IF_NONE_MATCH);

                                if (inm != null) {

                                    // Support: W/"etag", multiple values, spaces
                                    String normalizedInm = inm
                                            .replace("W/", "")
                                            .replace("\"", "")
                                            .trim();

                                    String normalizedEtag = etag
                                            .replace("\"", "")
                                            .trim();

                                    if (normalizedEtag.equals(normalizedInm)) {
                                        log.info("ETag match → 304 Not Modified");

                                        setStatusCode(HttpStatus.NOT_MODIFIED);
                                        // REQUIRED RFC CLEANUP
                                        h.remove(HttpHeaders.CONTENT_LENGTH);
                                        h.remove(HttpHeaders.CONTENT_TYPE);

                                        //REMOVE CSP & NONCE FOR 304 (BANK-GRADE HARDENING)
                                        h.remove("Content-Security-Policy");
                                        h.remove("X-CSP-Nonce");
                                        h.set(HttpHeaders.ETAG, etag);

                                        return setComplete();
                                    }
                                }

                                // Normal 200 with body
                                h.setContentLength(bytes.length);
                                return super.writeWith(Mono.just(bufferFactory().wrap(bytes)));

                            } catch (Exception e) {
                                log.error("ETag generation failed", e);
                                return errorResponseWriter.write(
                                        exchange,
                                        HttpStatus.INTERNAL_SERVER_ERROR,
                                        "ETag generation failed"
                                );
                            }
                        });
            }

            @Override
            public Mono<Void> writeAndFlushWith(
                    Publisher<? extends Publisher<? extends DataBuffer>> body) {
                return writeWith(Flux.from(body).flatMapSequential(Function.identity()));
            }
        };
        
        return chain.filter(exchange.mutate().response(decorated).build());
    }

    // Strong/CRC32C ETag
    private String computeEtag(byte[] bytes) throws Exception {
        if (props.isCryptoStrongEtag()) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(bytes);
            return "\"" + toHex(md.digest()) + "\"";
        }
        CRC32C crc = new CRC32C();
        crc.update(bytes, 0, bytes.length);
        return "\"crc32c-" + Long.toHexString(crc.getValue()) + "\"";
    }

    private static String toHex(byte[] digest) {
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
