package com.learn.api_gateway.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Data
@Component
@ConfigurationProperties(prefix = "security.headers")
@Validated
public class SecurityHeadersProperties {
	
	private Hsts hsts = new Hsts();
    private boolean cspEnabled = true;
    private String directives;
    private String permissionsPolicy;
    private String referrerPolicy;
    private String xssProtection;
    private String frameOptions;
    private String crossOriginOpenerPolicy;
    private String crossOriginEmbedderPolicy;
    private String crossOriginResourcePolicy;

    @Data
    public static class Hsts {
        private boolean enabled;
        private long maxAge;
        private boolean includeSubDomains;
        private boolean preload;
    }
}
