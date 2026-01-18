package com.learn.api_gateway.config.properties;

import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import com.learn.api_gateway.service.ReCaptchaValidator;

//import com.learn.api_gateway.service.ReCaptchaValidator;

import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

@Data
@Configuration
@ConfigurationProperties(prefix = "recaptcha")
@Validated
@Slf4j
public class RecaptchaConfigProperties {
	private String secretKey;

    private double minScore = 0.5;
    private Duration tokenTtl = Duration.ofMinutes(2);

    /**
     * Hostname allow-list.
     * Supports exact match ("frontend.example.com") or wildcard ("*.example.com").
     */
    private List<String> expectedHostnames = List.of();

    private List<String> expectedAction = List.of();

    /**
     * Global default fail mode (CLOSED = secure default).
     */
    private ReCaptchaValidator.FailMode failMode = ReCaptchaValidator.FailMode.CLOSED;

    /**
     * Per-endpoint fail mode overrides (explicit FailMode enum).
     */
    private Map<String, ReCaptchaValidator.FailMode> endpointFailModes = Map.of();

    /**
     * Backwards-compatible boolean fail-open map (default, login, signup, ...).
     * If present it will be honored before global failMode when deciding per-endpoint policy.
     */
    private Map<String, Boolean> failOpen = Map.of("default", false);

    private RateLimitProperties rateLimit = new RateLimitProperties();

    private String baseUrl = "https://www.google.com";
    private String expectedDomain = "frontend.example.com";
    private String loginAction = "login";
    private String signupAction = "signup";

    private Pool pool = new Pool();
    private Timeouts timeouts = new Timeouts();
    private Duration localCacheTtl = Duration.ofSeconds(30);

    private int maxAttemptsPerMinute = 5; // legacy / convenience

    private boolean failClosedOnRedisError = true;
    private boolean failClosedOnValidationError = true;

    /**
     * Optional Redis key prefix for replay protection.
     * Default: "RECAPTCHA_USED:"
     */
    private String replayPrefix = "RECAPTCHA_USED:";

    /**
     * Optional salt (e.g. env name or region code) for replay key isolation across environments.
     * Default: "default"
     */
    private String environmentSalt = "default";
    
    private Hmac hmac = new Hmac();
    
    private long bypassMinutes;

    // --- derived logic methods ---
    public boolean isFailOpenFor(String context) {
        return failOpen.getOrDefault(context, false);
    }

    public boolean isFailClosed(String endpointKey) {
        return getFailMode(endpointKey) == ReCaptchaValidator.FailMode.CLOSED;
    }

    public ReCaptchaValidator.FailMode getFailMode(String endpointKey) {
        if (endpointFailModes != null && endpointFailModes.containsKey(endpointKey)) {
            return endpointFailModes.get(endpointKey);
        }
        if (failOpen != null && failOpen.containsKey(endpointKey)) {
            return failOpen.get(endpointKey)
                    ? ReCaptchaValidator.FailMode.OPEN
                    : ReCaptchaValidator.FailMode.CLOSED;
        }
        if (failOpen != null && failOpen.containsKey("default")) {
            return failOpen.get("default")
                    ? ReCaptchaValidator.FailMode.OPEN
                    : ReCaptchaValidator.FailMode.CLOSED;
        }
        return failMode;
    }

    // --- expectedHostnames binding ---
    public void setExpectedHostnames(String single) {
        if (single == null || single.isBlank()) {
            this.expectedHostnames = List.of();
        } else {
            setExpectedHostnames(Arrays.asList(single.split(",")));
        }
    }

    public void setExpectedHostnames(List<String> list) {
        if (list == null) {
            this.expectedHostnames = List.of();
            return;
        }
        this.expectedHostnames = list.stream()
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(String::toLowerCase)
                .distinct()
                .collect(Collectors.toList());
    }
    
    public void setExpectedAction(String single) {
        if (single == null || single.isBlank()) {
            this.expectedAction = List.of();
        } else {
            setExpectedAction(Arrays.asList(single.split(",")));
        }
    }

    public void setExpectedAction(List<String> list) {
        if (list == null) {
            this.expectedAction = List.of();
            return;
        }
        this.expectedAction = list.stream()
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .distinct()
                .collect(Collectors.toList());
    }

    public boolean matchesHostname(String hostname) {
        if (hostname == null || hostname.isBlank()) {
            return false;
        }
        String normalized = hostname.toLowerCase(Locale.ROOT);
        return expectedHostnames.stream().anyMatch(expected -> {
            if (expected.startsWith("*.")) {
                String suffix = expected.substring(1); // remove '*'
                return normalized.endsWith(suffix);
            }
            return expected.equalsIgnoreCase(normalized);
        });
    }

    public Duration getRateLimitWindow() {
        return rateLimit.getFailureWindow() != null
                ? rateLimit.getFailureWindow()
                : Duration.ofSeconds(rateLimit.getWindowSeconds());
    }

    public int getRateLimitMaxFailures() {
        return rateLimit.getMaxFailuresBeforeCaptcha();
    }

    public boolean isEnableRateLimit() {
        return rateLimit != null && rateLimit.isEnabled();
    }

    public void normalize() {
        if (replayPrefix == null || replayPrefix.isBlank()) {
            replayPrefix = "RECAPTCHA_USED:";
        }
        if (environmentSalt == null || environmentSalt.isBlank()) {
            environmentSalt = "default";
        }
    }

    @Data
    public static class Pool {
        private int maxConnections = 50;
        private int pendingAcquireMaxCount = 100;
        private Duration maxIdleTime = Duration.ofSeconds(30);
        private Duration maxLifeTime = Duration.ofMinutes(2);
    }

    @Data
    public static class Timeouts {
        private Duration connect = Duration.ofSeconds(3);
        private Duration response = Duration.ofSeconds(5);
        private Duration read = Duration.ofSeconds(5);
        private Duration write = Duration.ofSeconds(5);
    }

    @Data
    public static class RateLimitProperties {
        private Duration failureWindow = Duration.ofMinutes(15);
        private int maxFailuresBeforeCaptcha = 5;
        private boolean enabled = false;
        private long windowSeconds = 60;
    }
    
    @Data
    public static class Hmac {
        private Map<String, String> secrets = new HashMap<>();
        private String defaultSecret;
        private String secondarySecret;
        private boolean fromConfigFile = true;
        private String algorithm = "HmacSHA256";
        private Set<String> allowedAlgorithms = Set.of("HmacSHA256", "HmacSHA512");
        private int signatureValiditySeconds;
    }
    
    @PostConstruct
    public void verifyConfig() {
        log.info("Loaded recaptcha.secret-key: {}", secretKey);
        log.info("Loaded recaptcha.hmac.default-secret: {}",
                hmac.getDefaultSecret() != null ? "****" : "MISSING");
    }
}
