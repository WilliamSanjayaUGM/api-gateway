package com.learn.api_gateway.filter;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.learn.api_gateway.config.properties.SecurityHeadersProperties;
import com.learn.api_gateway.dto.ApiError;
import com.learn.api_gateway.util.ReactorMdc;
import com.learn.api_gateway.util.TraceConstants;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class SecurityHeaderFilter implements GlobalFilter, Ordered {

    private final SecurityHeadersProperties props;
    private final ObjectMapper objectMapper;

    private static final Set<String> SAFE_MULTI_HEADERS = Set.of(
            "accept", "accept-language", "cookie", "set-cookie",
            "x-forwarded-for", "x-forwarded-proto", "x-real-ip", "vary"
    );

    private static final Pattern RFC7230_HEADER_NAME =
            Pattern.compile("^[!#$%&'*+.^_`|~0-9a-zA-Z-]+$");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        boolean invalidHeaderFound = exchange.getRequest().getHeaders().entrySet().stream()
                .anyMatch(entry -> {
                    String name = entry.getKey();
                    List<String> values = entry.getValue();

                    // CRLF Injection
                    boolean hasCrLf =
                            name.contains("\r") || name.contains("\n") ||
                            values.stream().anyMatch(v -> v.contains("\r") || v.contains("\n"));

                    // RFC7230 Header Name Violation
                    boolean invalidName = !RFC7230_HEADER_NAME.matcher(name).matches();

                    // Duplicate Header Poisoning (non-safe headers)
                    boolean duplicatePoison =
                            values.size() > 1 && !SAFE_MULTI_HEADERS.contains(name.toLowerCase());

                    if (duplicatePoison) {
                        log.warn("Duplicate header poisoning detected: {} -> {}", name, values);
                    }

                    return hasCrLf || invalidName || duplicatePoison;
                });
        
        if (invalidHeaderFound) {
            String client = Optional.ofNullable(exchange.getRequest().getRemoteAddress())
                    .map(Object::toString).orElse("unknown");
            String traceId = Optional.ofNullable(exchange.getAttribute(TraceConstants.TRACE_ID_CONTEXT_KEY))
                    .map(Object::toString).orElse(UUID.randomUUID().toString());

            log.warn("[traceId={}] Blocked invalid headers from {}", traceId, client);

            ApiError apiError = ApiError.of(Instant.now(), 400, "Bad Request", "Invalid header", traceId);
            exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);
            exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

            try {
                byte[] bytes = objectMapper.writeValueAsBytes(apiError);
                return exchange.getResponse()
                        .writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
            } catch (Exception e) {
                return exchange.getResponse().setComplete();
            }
        }

        ServerHttpResponse response = exchange.getResponse();
        HttpHeaders headers = response.getHeaders();
        
        // DO NOT APPLY CSP ON 304
        response.beforeCommit(() -> {
            if (response.getStatusCode() == HttpStatus.NOT_MODIFIED) {
                headers.remove("Content-Security-Policy");
                headers.remove("X-CSP-Nonce");
            }
            return Mono.empty();
        });

        // HSTS
        if ("https".equalsIgnoreCase(exchange.getRequest().getURI().getScheme())) {
            headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
        }

        // Core Browser Defenses
        headers.set("X-Frame-Options", props.getFrameOptions());
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-XSS-Protection", props.getXssProtection());
        headers.set("Referrer-Policy", props.getReferrerPolicy());
        headers.set("X-DNS-Prefetch-Control", "off");

        // Cross-Origin Isolation
        headers.set("Cross-Origin-Opener-Policy", props.getCrossOriginOpenerPolicy());
        headers.set("Cross-Origin-Embedder-Policy", props.getCrossOriginEmbedderPolicy());
        headers.set("Cross-Origin-Resource-Policy", props.getCrossOriginResourcePolicy());

        // Permissions Policy
        headers.set("Permissions-Policy",
                Optional.ofNullable(props.getPermissionsPolicy())
                        .filter(s -> !s.isBlank())
                        .orElse("geolocation=(), microphone=(), camera=(), fullscreen=(self), payment=()"));

        // Anti-Cache Poisoning
        headers.set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        headers.set("Pragma", "no-cache");
        headers.set("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers");

        // Certificate Transparency
        headers.set("Expect-CT", "max-age=86400, enforce");

        // CSP with Nonce
        if (props.isCspEnabled()) {
            String nonce = Base64.getEncoder().encodeToString(new SecureRandom().generateSeed(16));
            exchange.getAttributes().put("cspNonce", nonce);

            String csp = Optional.ofNullable(props.getDirectives())
                    .filter(s -> !s.isBlank())
                    .map(s -> s.replace("{nonce}", nonce))
                    .orElse("default-src 'self'; script-src 'nonce-" + nonce + "'");

            headers.set("Content-Security-Policy", csp);
            headers.set("X-CSP-Nonce", nonce);
        }

        // Stack Fingerprint Removal
        headers.remove("Server");
        headers.remove("X-Powered-By");

        log.info("------------SecurityHeaderFilter PASSED X-Forwarded-For {}-------------",exchange.getRequest().getHeaders().getFirst("X-Forwarded-For"));

        return chain.filter(exchange)
                .transformDeferred(ReactorMdc.mdcOperatorVoid());
    }

    @Override
    public int getOrder() {
        return -950;
    }
}