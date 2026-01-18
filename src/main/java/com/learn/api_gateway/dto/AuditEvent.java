package com.learn.api_gateway.dto;

import java.time.Instant;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@AllArgsConstructor
@Builder
public class AuditEvent {
	private Instant ts;
    private String level;             // INFO/WARN/ERROR
    private String event;             // e.g., "TOKEN_REVOKED", "CAPTCHA_FAILED"
    private String userId;            // hashed if needed
    private String clientIp;
    private String route;
    private String detail;            // short message
    private Map<String, Object> meta;
}
