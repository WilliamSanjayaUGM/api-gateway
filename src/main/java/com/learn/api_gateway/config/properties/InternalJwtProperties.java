package com.learn.api_gateway.config.properties;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Configuration
@Data
@ConfigurationProperties(prefix = "security.internal-jwt")
public class InternalJwtProperties {

    private String issuer;
    private long ttlSeconds = 60;

    /** keyId -> base64 key */
    private Map<String, String> keys = new HashMap<>();

    private String activeKeyId;
}
