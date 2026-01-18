package com.learn.api_gateway.introspector;

import java.util.Locale;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.learn.api_gateway.filter.OpaqueTokenClaimPropagatingFilter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Used inside introspect CachingRevocationAwareIntrospector
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class LocalRevocationEvictor {
	
	private final OpaqueTokenClaimPropagatingFilter opaqueFilter;
    private final ObjectMapper objectMapper;

    /**
     * Reactive entry point for handling revocation payloads.
     * Can handle both structured JSON (type/key) and raw token hashes.
     */
    public Mono<Void> handleRevocationPayload(String payload) {
        if (payload == null || payload.isBlank()) {
            log.warn("Received empty revocation payload");
            return Mono.empty();
        }

        return Mono.fromRunnable(() -> {
            try {
                JsonNode node = tryParseJson(payload);

                if (node != null && node.hasNonNull("type") && node.hasNonNull("key")) {
                    handleStructuredPayload(node);
                } else {
                    handleRawPayload(payload);
                }

            } catch (Exception ex) {
                log.error("Failed to handle revocation payload: {}", payload, ex);
            }
        });
    }

    private void handleStructuredPayload(JsonNode node) {
        String type = node.get("type").asText("").toUpperCase(Locale.ROOT);
        String key = node.get("key").asText("");

        switch (type) {
            case "TOKEN" -> {
                String canonicalTokenKey = canonicalizeTokenKey(key);
                opaqueFilter.evictTokenIfPresent(canonicalTokenKey);
                log.info("Evicted token cache for key={}", canonicalTokenKey);
            }
            case "USER" -> {
                String canonicalUserKey = canonicalizeUserKey(key);
                opaqueFilter.evictUserIfPresent(canonicalUserKey);
                log.info("Evicted user cache for key={}", canonicalUserKey);
            }
            default -> log.warn("Unknown revocation type '{}'", type);
        }
    }

    private void handleRawPayload(String payload) {
        String canonicalTokenKey = canonicalizeTokenKey(payload);
        opaqueFilter.evictTokenIfPresent(canonicalTokenKey);
        log.info("Evicted local token cache for raw key={}", canonicalTokenKey);
    }

    private JsonNode tryParseJson(String json) {
        try {
            return objectMapper.readTree(json);
        } catch (Exception e) {
            return null;
        }
    }

    private static String canonicalizeTokenKey(String key) {
        final String prefix = "revoked:token:";
        return key.startsWith(prefix) ? key.substring(prefix.length()) : key;
    }

    private static String canonicalizeUserKey(String key) {
        final String prefix = "revoked:user:";
        return key.startsWith(prefix) ? key.substring(prefix.length()) : key;
    }
}
