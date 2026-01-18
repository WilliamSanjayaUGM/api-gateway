package com.learn.api_gateway.service;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.learn.api_gateway.config.properties.RecaptchaConfigProperties;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class HmacService {
	
	private static final int MIN_KEY_BYTES = 32; // 256-bit minimum
    private static final Charset UTF8 = StandardCharsets.UTF_8;

    private final RecaptchaConfigProperties props;
    private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
    private final ObjectMapper objectMapper;

    @Value("${spring.profiles.active:default}")
    private String activeProfile;

    private volatile SecretKeySpec activeKeySpec;
    private ThreadLocal<Mac> macThreadLocal;

    @PostConstruct
    public void init() {
        log.info("Initializing HmacService (profile={})...", activeProfile);

        String defaultSecret = props.getHmac().getDefaultSecret();
        if (defaultSecret == null || defaultSecret.isBlank()) {
            throw new IllegalStateException("Missing default HMAC secret");
        }

        this.activeKeySpec = toKeySpec(defaultSecret, "default");
        this.macThreadLocal = ThreadLocal.withInitial(() -> initMac(activeKeySpec));

        log.info("HmacService initialized with algorithm={} ({} bytes)",
                props.getHmac().getAlgorithm(), activeKeySpec.getEncoded().length);
    }

    /**
     * Signs payload and returns a versioned signature: version:base64(HMAC)
     */
    public Mono<String> sign(String payload, String keyVersion) {
        ensureInitialized();
        
        return resolveKeySpec(keyVersion)
                .map(keySpec -> {                	 
                    byte[] signature = signBytes(payload, keySpec);
                    return keyVersion + ":" + Base64.getEncoder().encodeToString(signature);
                });
    }

    /**
     * Verifies versioned HMAC signature.
     */
    public Mono<Boolean> verify(String payload, String versionedSignature) {
        ensureInitialized();
        String traceId = Optional.ofNullable(MDC.get("X-Trace-Id")).orElse("N/A");

        if (versionedSignature == null || !versionedSignature.contains(":")) {
            log.warn("[traceId={}] Invalid signature format", traceId);
            return Mono.just(false);
        }

        String[] parts = versionedSignature.split(":", 2);
        String keyVersion = parts[0];
        String providedSignature = parts[1];
        
        // 1. Extract timestamp from payload (e.g., "timestamp": 1730959923)
        Instant requestTimestamp = extractTimestampFromPayload(payload);
        if (requestTimestamp == null) {
            log.warn("[traceId={}] No timestamp found in payload", traceId);
            return Mono.just(false);
        }

        // 2. Check expiration based on configured validity seconds
        if (Duration.between(requestTimestamp, Instant.now()).abs().getSeconds() > props.getHmac().getSignatureValiditySeconds()) {
            log.warn("[traceId={}] Request signature expired (timestamp={})", traceId, requestTimestamp);
            return Mono.just(false);
        }
        
        // 3. Validate HMAC signature
        return resolveKeySpec(keyVersion)
                .map(keySpec -> {
                    byte[] expectedBytes = signBytes(payload, keySpec);
                    byte[] providedBytes = Base64.getDecoder().decode(providedSignature);
                    return MessageDigest.isEqual(expectedBytes, providedBytes);
                })
                .onErrorResume(e -> {
                    log.warn("[traceId={}] HMAC verification failed: {}", traceId, e.getMessage());
                    return Mono.just(false);
                });
    }
    
    /**
     * Extracts a timestamp (ISO 8601 or epoch seconds) from JSON payload.
     * Assumes payload contains a field "timestamp".
     */
    private Instant extractTimestampFromPayload(String payload) {
        try {
            JsonNode node = objectMapper.readTree(payload);
            if (node.has("timestamp")) {
                JsonNode tsNode = node.get("timestamp");
                if (tsNode.isNumber()) {
                    return Instant.ofEpochSecond(tsNode.asLong());
                } else if (tsNode.isTextual()) {
                    return Instant.parse(tsNode.asText());
                }
            }
        } catch (Exception e) {
            log.debug("Failed to parse timestamp from payload: {}", e.getMessage());
        }
        return null;
    }

    private Mono<SecretKeySpec> resolveKeySpec(String keyId) {
        String traceId = Optional.ofNullable(MDC.get("X-Trace-Id")).orElse("N/A");
        
        return reactiveRedisTemplate.opsForValue()
                .get("hmac:key:" + keyId)
                .onErrorResume(e -> {
                    log.warn("[traceId={}] Redis unavailable → This line 146 is really the one causing issueeee prove it!!!! fallback to config", traceId);
                    return Mono.empty();
                })
                .defaultIfEmpty(props.getHmac().getSecrets().getOrDefault(keyId, props.getHmac().getDefaultSecret()))
                .map(base64Key -> {
                    if (base64Key == null || base64Key.isBlank()) {
                        throw new IllegalStateException("[traceId=" + traceId + "] No HMAC key for isuuuuueeeee keyId=" + keyId);
                    }
                    return toKeySpec(base64Key, keyId);
                });
    }

    private byte[] signBytes(String payload, SecretKeySpec keySpec) {
        try {
            Mac mac = macThreadLocal.get();
            Mac worker;
            try {
                worker = (Mac) mac.clone();
            } catch (CloneNotSupportedException ex) {
                worker = Mac.getInstance(mac.getAlgorithm());
                worker.init(keySpec);
            }
            return worker.doFinal(payload.getBytes(UTF8));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute HMAC", e);
        }
    }

    private SecretKeySpec toKeySpec(String base64Secret, String label) {
        byte[] keyBytes = null;
        try {
            keyBytes = Base64.getDecoder().decode(base64Secret);
            if (keyBytes.length < MIN_KEY_BYTES) {
                throw new IllegalArgumentException(
                        label + " HMAC key too weak: " + keyBytes.length + " bytes (min " + MIN_KEY_BYTES + ")");
            }
            return new SecretKeySpec(keyBytes, props.getHmac().getAlgorithm());
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid " + label + " HMAC secret", e);
        } finally {
            if (keyBytes != null) Arrays.fill(keyBytes, (byte) 0);
        }
    }

    private Mac initMac(SecretKeySpec keySpec) {
        try {
            Mac mac = Mac.getInstance(props.getHmac().getAlgorithm());
            mac.init(keySpec);
            return mac;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize Mac with " + props.getHmac().getAlgorithm(), e);
        }
    }

    private void ensureInitialized() {
        if (macThreadLocal == null || activeKeySpec == null) {
            throw new IllegalStateException("HmacService not initialized");
        }
    }

    @PreDestroy
    public void clear() {
        if (activeKeySpec != null) Arrays.fill(activeKeySpec.getEncoded(), (byte) 0);
        macThreadLocal = null;
        log.info("HmacService secrets cleared from memory");
    }
}
