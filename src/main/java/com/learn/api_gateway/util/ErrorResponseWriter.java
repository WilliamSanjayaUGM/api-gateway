package com.learn.api_gateway.util;

import java.time.Instant;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class ErrorResponseWriter {
	private final ObjectMapper objectMapper;

	public Mono<Void> write(ServerWebExchange exchange, HttpStatus status, String message) {
		ServerHttpResponse response = exchange.getResponse();
		
        if (response.isCommitted()) {
            log.warn("Response already committed. Skipping error write. status={} msg={}",
                    status, message);
            return Mono.empty();
        }

        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> body = Map.of(
                "timestamp", Instant.now().toString(),
                "status", status.value(),
                "error", status.getReasonPhrase(),
                "message", message,
                "traceId", exchange.getAttributeOrDefault(
                        TraceConstants.TRACE_ID_CONTEXT_KEY, "N/A")
        );

        try {
            byte[] json = objectMapper.writeValueAsBytes(body);
            return response.writeWith(
                    Mono.just(response.bufferFactory().wrap(json))
            );
        } catch (Exception e) {
            log.error("Failed writing error response", e);
            return response.setComplete();
        }
    }

//	private Mono<String> resolveTraceId(ServerWebExchange exchange) {
//        return Mono.deferContextual(ctx -> {
//                if (ctx.hasKey(TraceConstants.TRACE_ID_CONTEXT_KEY)) {
//                    return Mono.justOrEmpty((String) ctx.get(TraceConstants.TRACE_ID_CONTEXT_KEY));
//                }
//                return Mono.empty();
//            })
//            .onErrorResume(e -> Mono.empty())
//            .switchIfEmpty(Mono.justOrEmpty((String) exchange.getAttribute(TraceConstants.TRACE_ID_CONTEXT_KEY)))
//            .switchIfEmpty(Mono.justOrEmpty(MDC.get(TraceConstants.TRACE_ID_HEADER)))
//            .defaultIfEmpty("unknown");
//    }
}
