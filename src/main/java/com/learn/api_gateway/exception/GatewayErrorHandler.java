package com.learn.api_gateway.exception;

import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

import com.learn.api_gateway.util.ErrorResponseWriter;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Component
@Order(-2) // Higher priority than DefaultErrorWebExceptionHandler
@Slf4j
public class GatewayErrorHandler implements ErrorWebExceptionHandler {

    private final ErrorResponseWriter errorResponseWriter;

    public GatewayErrorHandler(ErrorResponseWriter errorResponseWriter) {
        this.errorResponseWriter = errorResponseWriter;
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {

        if (exchange.getResponse().isCommitted()) {
            log.debug("Response already committed – skipping error handling");
            return Mono.empty();
        }

        HttpStatus status = mapStatus(ex);
        String message = mapMessage(ex);

        log.warn("Gateway error [{}]: {}", status.value(), message);

        return errorResponseWriter.write(exchange, status, message);
    }

    private HttpStatus mapStatus(Throwable ex) {
        if (ex instanceof RuntimeException) return HttpStatus.BAD_REQUEST;
        if (ex instanceof AuthenticationException) return HttpStatus.UNAUTHORIZED;
        if (ex instanceof AccessDeniedException) return HttpStatus.FORBIDDEN;
        if (ex instanceof ResponseStatusException rse)
            return HttpStatus.valueOf(rse.getStatusCode().value());
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }

    private String mapMessage(Throwable ex) {
        if (ex instanceof RuntimeException wbe) return wbe.getMessage();
        if (ex instanceof AuthenticationException) return "Authentication failed";
        if (ex instanceof AccessDeniedException) return "Access denied";
        if (ex instanceof ResponseStatusException rse && rse.getReason() != null)
            return rse.getReason();
        return "Unexpected gateway error";
    }
}
