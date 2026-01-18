package com.learn.api_gateway.filter;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.learn.api_gateway.util.TraceConstants;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * This one for logging filters, not for modifying actual request flow. Log inbound/outbound safely
 */
@Slf4j
@Component
public class SecureLoggingFilter implements GlobalFilter, Ordered {

    public static final String TRACE_ID = "X-Trace-Id";
    public static final String ATTR_CLIENT_FINGERPRINT = "security.clientFingerprint";
    public static final String HEADER_CLIENT_IP = "X-Forwarded-For";

    /**
     * Headers that must never appear in plaintext logs.
     */
    private static final Set<String> SENSITIVE_HEADERS = Set.of(
            "Authorization", "Cookie", "X-Api-Key", "Proxy-Authorization"
    );
    
    @Override
    public int getOrder() {
    	return Ordered.LOWEST_PRECEDENCE;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        ServerHttpRequest request = exchange.getRequest();
        HttpHeaders masked = sanitizeHeaders(request.getHeaders());

        String method = request.getMethod() != null ? request.getMethod().name() : "UNKNOWN";
        String path = request.getURI().getPath();
        
        String traceId = (String) exchange.getAttribute(TraceConstants.TRACE_ID_CONTEXT_KEY);
        
        String fingerprint = (String) exchange.getAttribute(ATTR_CLIENT_FINGERPRINT);
        
        String ip = (String) exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP);

        log.info("""
                [REQ] traceId={} fingerprint={} clientIp={} method={} path={} headers={}
                """.strip(),
                traceId, fingerprint, ip, method, path, masked);

        return chain.filter(exchange)
                .doOnSuccess(done -> {
                    var status = exchange.getResponse().getStatusCode();
                    log.info("[RES] traceId={} fingerprint={} clientIp={} method={} path={} status={}",
                            traceId, fingerprint, ip, method, path, status);
                });
    }

    /**
     * Masks sensitive headers and protects against log injection.
     */
    private HttpHeaders sanitizeHeaders(HttpHeaders headers) {
        HttpHeaders sanitized = new HttpHeaders();

        headers.forEach((key, values) -> {
            String normalizedKey = key.trim();

            if (SENSITIVE_HEADERS.contains(normalizedKey)) {
                sanitized.add(normalizedKey, "[REDACTED]");
            } else {
                sanitized.add(
                        normalizedKey,
                        values.stream()
                                .map(v -> v.replaceAll("[\\r\\n]", "")) // prevent CRLF log injection
                                .collect(Collectors.joining(","))
                );
            }
        });

        return sanitized;
    }
}
