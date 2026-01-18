package com.learn.api_gateway.service;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.learn.api_gateway.dto.AuditEvent;

import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.scheduler.Schedulers;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditService {
	private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
    private final MeterRegistry meterRegistry;
    private final ObjectMapper objectMapper;

    private static final String AUDIT_CHANNEL = "gateway:audit";

    public void auditInfo(String event, String userId, String clientIp, String route, String detail, Map<String, Object> meta) {
        audit("INFO", event, userId, clientIp, route, detail, meta);
    }

    public void auditWarn(String event, String userId, String clientIp, String route, String detail, Map<String, Object> meta) {
        audit("WARN", event, userId, clientIp, route, detail, meta);
    }

    public void auditError(String event, String userId, String clientIp, String route, String detail, Map<String, Object> meta) {
        audit("ERROR", event, userId, clientIp, route, detail, meta);
    }

    private void audit(String level, String event, String userId, String clientIp, String route, String detail, Map<String, Object> meta) {
        AuditEvent ae = new AuditEvent(
                Instant.now(),
                level,
                event,
                userId,
                clientIp,
                route,
                detail,
                meta == null ? Collections.emptyMap() : meta
        );

        try {
            String payload = objectMapper.writeValueAsString(ae);

            // 1 Structured, searchable log
            log.info("[AUDIT] {}", payload);

            // 2 Publish asynchronously with safe error handling
            if (reactiveRedisTemplate != null) {
                reactiveRedisTemplate.convertAndSend(AUDIT_CHANNEL, payload)
                    .doOnError(err -> log.warn("Failed to publish audit to Redis: {}", err.getMessage(), err))
                    .subscribeOn(Schedulers.boundedElastic()) // prevents blocking event loop
                    .subscribe(
                        successCount -> log.debug("Audit event published successfully: {}", successCount),
                        err -> log.warn("Audit Redis publish error", err)
                    );
            }

            // 3 Increment metrics
            meterRegistry.counter("gateway.audit.events", "event", event, "level", level).increment();

        } catch (JsonProcessingException e) {
            log.error("Failed to serialize audit event", e);
        }
    }
}
