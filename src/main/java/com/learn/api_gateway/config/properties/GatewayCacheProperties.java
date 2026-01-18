package com.learn.api_gateway.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import lombok.Data;

@Data
@Configuration
@ConfigurationProperties(prefix = "gateway.cache")
@Validated
public class GatewayCacheProperties {
	/**
     * Max size for body ETag calculation in bytes (default 2MB).
     */
    private long maxEtagBodySize = 1_000_000; // 1 MB default

    /**
     * Default Cache-Control if not overridden per-route.
     */
    private String cacheControl = "public, max-age=3600";

    /**
     * Default TTL in seconds if no cache-control provided.
     */
    private long defaultTtl = 600;

    /**
     * Enable ETag by default.
     */
    private boolean etagEnabled = true;

    /**
     * Generate Last-Modified header by default.
     */
    private boolean lastModifiedEnabled = false;

    /**
     * Skip ETag if Content-Length missing.
     */
    private boolean skipIfNoContentLength = true;
    
    private boolean cryptoStrongEtag = false;
}
