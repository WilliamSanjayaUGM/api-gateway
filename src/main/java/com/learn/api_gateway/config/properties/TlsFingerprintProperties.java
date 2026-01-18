package com.learn.api_gateway.config.properties;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Data
@Configuration
@ConfigurationProperties(prefix = "security.tls-fingerprint")
public class TlsFingerprintProperties {

    /**
     * Enable / disable TLS fingerprint anomaly detection.
     */
    private boolean enabled = true;

    /**
     * Known-bad JA3 fingerprints (bot frameworks, scanners, malware).
     */
    private Set<String> knownBadJa3 = new HashSet<>();

    /**
     * JA3 fingerprints that look like curl / python / openssl
     * but are seen together with browser User-Agents.
     */
    private Set<String> curlLikeJa3 = new HashSet<>();

    /**
     * Substrings or regex fragments that indicate TLS downgrade
     * or abnormal JA4 traits.
     *
     * Example: TLSv1.0, weak cipher ordering, missing extensions.
     */
    private List<String> downgradePatterns = new ArrayList<>();

    /**
     * If true, missing JA3 on INTERNAL traffic increases risk.
     * (Never blocks directly.)
     */
    private boolean requireJa3ForInternal = true;

    /**
     * Maximum risk score this filter may contribute.
     * Prevents runaway scoring.
     */
    private int maxRiskScore = 100;

    /**
     * Whether this filter should only score (recommended),
     * never hard-block traffic.
     */
    private boolean scoreOnly = true;
}