package com.learn.api_gateway.util;

import java.util.List;
import java.util.function.Function;

import org.reactivestreams.Publisher;
import org.slf4j.MDC;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.context.ContextView;

public final class ReactorMdc {
	private ReactorMdc() {}

    private static final List<String> KEYS_TO_PROPAGATE = List.of(
        TraceConstants.TRACE_ID_CONTEXT_KEY,
        TraceConstants.CLIENT_IP_CONTEXT_KEY,
        TraceConstants.USER_ID_CONTEXT_KEY
    );

    // === REACTOR MDC OPERATOR ===
    public static <T> Function<Publisher<T>, Publisher<T>> mdcOperator() {
        return publisher -> {
            if (publisher instanceof Mono<?>) {
                @SuppressWarnings("unchecked")
                Mono<T> mono = (Mono<T>) publisher;
                return mono
                        .doOnEach(signal -> {
                            if (!signal.isOnComplete() && signal.getContextView() != null) {
                                copyToMdc(signal.getContextView());
                            }
                        })
                        .doFinally(sig -> MDC.clear());
            } else if (publisher instanceof Flux<?>) {
                @SuppressWarnings("unchecked")
                Flux<T> flux = (Flux<T>) publisher;
                return flux
                        .doOnEach(signal -> {
                            if (!signal.isOnComplete() && signal.getContextView() != null) {
                                copyToMdc(signal.getContextView());
                            }
                        })
                        .doFinally(sig -> MDC.clear());
            } else {
                // fallback for any other Publisher type
                return publisher;
            }
        };
    }

    private static void copyToMdc(ContextView ctx) {
        if (ctx == null) return;
        for (String key : KEYS_TO_PROPAGATE) {
            ctx.getOrEmpty(key).ifPresent(value -> MDC.put(key, String.valueOf(value)));
        }
    }

    /**
     * For Mono<Void> usages (e.g., in filters)
     */
    public static Function<Mono<Void>, Mono<Void>> mdcOperatorVoid() {
        return mono -> mono
                .doOnEach(signal -> {
                    if (!signal.isOnComplete() && signal.getContextView() != null) {
                        copyToMdc(signal.getContextView());
                    }
                })
                .doFinally(sig -> MDC.clear());
    }

    /**
     * WebClient filter for propagating MDC headers
     */
    public static ExchangeFilterFunction webClientFilter() {
        return ExchangeFilterFunction.ofRequestProcessor(request ->
                Mono.deferContextual(ctx -> {
                    ClientRequest.Builder builder = ClientRequest.from(request);
                    KEYS_TO_PROPAGATE.forEach(key ->
                            ctx.getOrEmpty(key).ifPresent(value ->
                                    builder.header(mapContextKeyToHeader(key), value.toString())
                            )
                    );
                    return Mono.just(builder.build());
                })
        );
    }

    private static String mapContextKeyToHeader(String key) {
        return switch (key) {
            case TraceConstants.TRACE_ID_CONTEXT_KEY -> TraceConstants.TRACE_ID_HEADER;
            case TraceConstants.CLIENT_IP_CONTEXT_KEY -> "X-Client-Ip";
            case TraceConstants.USER_ID_CONTEXT_KEY -> "X-User-Id";
            default -> key;
        };
    }
}
