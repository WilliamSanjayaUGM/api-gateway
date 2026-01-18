package com.learn.api_gateway.filter;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import org.slf4j.MDC;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.learn.api_gateway.util.TraceConstants;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class TraceIdFilter implements GlobalFilter, Ordered{
	
	private static final int MAX_TRACE_ID_LENGTH = 128;
    private static final String TRACEPARENT_HEADER = "traceparent";
    private static final String SPAN_ID_CONTEXT_KEY = "trace.spanId";
    private static final String PARENT_SPAN_ID_CONTEXT_KEY = "trace.parentSpanId";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        HttpHeaders headers = exchange.getRequest().getHeaders();

        // Extract existing traceId or fallback
        String traceId = extractTraceIdFromTraceParent(headers.getFirst(TRACEPARENT_HEADER))
                .or(() -> sanitizeTraceId(headers.getFirst(TraceConstants.TRACE_ID_HEADER)))
                .orElseGet(this::generateTraceId);
        
        log.info("------------TraceIdFilter X-Forwarded-For {}-------------",exchange.getRequest().getHeaders().getFirst("X-Forwarded-For"));

        // Extract upstream spanId as parent
        String parentSpanId = extractSpanIdFromTraceParent(headers.getFirst(TRACEPARENT_HEADER)).orElse(null);
        // Generate new spanId for this hop
        String spanId = generateSpanId();

        // Mutate headers for downstream propagation
        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(r -> r.headers(h -> {
                    h.set(TraceConstants.TRACE_ID_HEADER, traceId);
                    h.set(TRACEPARENT_HEADER, buildTraceParent(traceId, spanId));
                    if (parentSpanId != null) {
                        h.set("X-Parent-SpanId", parentSpanId); // optional debug header
                    }
                }))
                .build();

        // Store attributes for access by ErrorResponseWriter, log filters, etc.
        mutatedExchange.getAttributes().put(TraceConstants.TRACE_ID_CONTEXT_KEY, traceId);
        mutatedExchange.getAttributes().put(SPAN_ID_CONTEXT_KEY, spanId);
        if (parentSpanId != null) {
            mutatedExchange.getAttributes().put(PARENT_SPAN_ID_CONTEXT_KEY, parentSpanId);
        }

        // Bind to Reactor Context + MDC
        return chain.filter(mutatedExchange)
                .contextWrite(ctx -> {
                    // Reactor context
                    ctx = ctx.put(TraceConstants.TRACE_ID_CONTEXT_KEY, traceId);
                    ctx = ctx.put(SPAN_ID_CONTEXT_KEY, spanId);
                    if (parentSpanId != null) {
                        ctx = ctx.put(PARENT_SPAN_ID_CONTEXT_KEY, parentSpanId);
                    }

                    // Bind MDC so logs automatically include X-Trace-Id
                    MDC.put(TraceConstants.TRACE_ID_HEADER, traceId);
                    
                    log.info("------------This is TraceIdFilter -------------");
                    return ctx;
                })
                .doFinally(signal -> MDC.remove(TraceConstants.TRACE_ID_HEADER)); // cleanup to avoid leak
    }

    private Optional<String> sanitizeTraceId(String traceId) {
        if (traceId == null || traceId.isBlank()) return Optional.empty();
        if (traceId.length() > MAX_TRACE_ID_LENGTH) {
            log.warn("Inbound traceId too long ({} chars), generating new traceId", traceId.length());
            return Optional.empty();
        }
        if (!traceId.matches("^[a-zA-Z0-9\\-_.:]+$")) {
            log.warn("Inbound traceId has invalid format: {}", traceId);
            return Optional.empty();
        }
        return Optional.of(traceId);
    }

    private String generateTraceId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    private String generateSpanId() {
        return String.format("%016x", ThreadLocalRandom.current().nextLong());
    }

    private Optional<String> extractTraceIdFromTraceParent(String traceParent) {
        if (traceParent == null || traceParent.isBlank()) return Optional.empty();
        String[] parts = traceParent.split("-");
        if (parts.length < 4) return Optional.empty();
        String traceId = parts[1];
        if (traceId.matches("^[a-f0-9]{32}$")) {
            return Optional.of(traceId);
        }
        return Optional.empty();
    }

    private Optional<String> extractSpanIdFromTraceParent(String traceParent) {
        if (traceParent == null || traceParent.isBlank()) return Optional.empty();
        String[] parts = traceParent.split("-");
        if (parts.length < 4) return Optional.empty();
        String spanId = parts[2];
        if (spanId.matches("^[a-f0-9]{16}$")) {
            return Optional.of(spanId);
        }
        return Optional.empty();
    }

    private String buildTraceParent(String traceId, String spanId) {
        return "00-" + traceId + "-" + spanId + "-01";
    }

    @Override
    public int getOrder() {
        return -1000; // run before security and logging filters
    }
}
