package com.learn.api_gateway.config.properties;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@Data
@Validated
@ConfigurationProperties(prefix = "security.user-agent")
@Configuration
public class UserAgentFingerprintProperties {

    /**
     * Master switch.
     */
    private boolean enabled = true;

    /**
     * Minimum allowed UA length to avoid empty / trivial / probe UAs.
     */
    @Min(5)
    private int minLength = 10;

    /**
     * Max allowed UA length to prevent header abuse / buffer issues.
     */
    @Max(1024)
    private int maxLength = 512;

    /**
     * Case-insensitive regex patterns that are outright blocked.
     * e.g., scanners, CLI clients, obvious bots.
     */
    private List<String> blockedPatterns = List.of(
            "curl",
            "wget",
            "sqlmap",
            "nikto",
            "acunetix",
            "nessus",
            "burp",
            "nmap",
            "massscan"
    );

    /**
     * Optional allow-list of patterns for strict environments.
     * If empty, no allowlist enforcement.
     */
    private List<String> allowedPatterns = List.of();

    /**
     * Whether internal traffic (e.g., from inside cluster) can have empty UA.
     * You can refine "internal" in the filter logic (IP ranges, etc.).
     */
    private boolean allowEmptyForInternal = true;

    /**
     * What header we will expose the fingerprint on.
     */
    @NotBlank
    private String fingerprintHeaderName = "X-Client-Fingerprint";

    /**
     * HMAC secret for fingerprinting (must be non-null in prod).
     * Load via environment / vault, never hardcode.
     */
    @NotBlank
    private String fingerprintHmacSecret;

    /**
     * Maximum number of distinct characters to avoid super noisy UAs.
     * Optional, but useful to mitigate obfuscated probes.
     */
    @Max(128)
    private int maxDistinctChars = 80;
    
    private boolean requireJa3ForPrivateApis = true;
    
    // TLS / JA3 support (optional, only works if ingress sets header)
    private String ja3HeaderName = "X-JA3-Fingerprint";
    private boolean requireJa3ForPublic = false;
    private List<String> allowedJa3Fingerprints = List.of();

    // UA consistency checks
    private boolean enableUaConsistencyCheck = false;
    private boolean blockOnUaInconsistency = false;  
}