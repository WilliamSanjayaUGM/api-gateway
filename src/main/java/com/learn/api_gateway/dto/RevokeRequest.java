package com.learn.api_gateway.dto;

public record RevokeRequest(String token, Long expiresAt, Long ttlSeconds) {
}
