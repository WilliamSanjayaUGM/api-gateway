package com.learn.api_gateway.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;

@Validated
@ConfigurationProperties(prefix = "security.cache")
@Configuration
public class SecurityCacheProperties {
	/**
     * TTL (in minutes) for introspection cache entries (principal details).
     * Helps reduce load on Keycloak or OAuth2 Introspection endpoint.
     */
    @Min(1)
    private long introspectionCacheTtlMinutes = 5;

    /**
     * TTL (in minutes) for revoked token cache entries.
     * Determines how long a revoked token remains in Redis before expiry.
     */
    @Min(1)
    private long revokedTokenCacheTtlMinutes = 10;

    /**
     * Optional TTL for JWK or signing key cache (for public key rotation scenarios).
     */
    @Min(1)
    private long keyCacheTtlMinutes = 60;

    // --- Getters & Setters ---
    public long getIntrospectionCacheTtlMinutes() {
        return introspectionCacheTtlMinutes;
    }

    public void setIntrospectionCacheTtlMinutes(long introspectionCacheTtlMinutes) {
        this.introspectionCacheTtlMinutes = introspectionCacheTtlMinutes;
    }

    public long getRevokedTokenCacheTtlMinutes() {
        return revokedTokenCacheTtlMinutes;
    }

    public void setRevokedTokenCacheTtlMinutes(long revokedTokenCacheTtlMinutes) {
        this.revokedTokenCacheTtlMinutes = revokedTokenCacheTtlMinutes;
    }

    public long getKeyCacheTtlMinutes() {
        return keyCacheTtlMinutes;
    }

    public void setKeyCacheTtlMinutes(long keyCacheTtlMinutes) {
        this.keyCacheTtlMinutes = keyCacheTtlMinutes;
    }

    // --- Helper methods for safety ---
    public long getSafeTtlMinutes() {
        return Math.max(introspectionCacheTtlMinutes, 1L);
    }

    public long getSafeRevokedTtlMinutes() {
        return Math.max(revokedTokenCacheTtlMinutes, 1L);
    }

    public long getSafeKeyCacheTtlMinutes() {
        return Math.max(keyCacheTtlMinutes, 1L);
    }
}
