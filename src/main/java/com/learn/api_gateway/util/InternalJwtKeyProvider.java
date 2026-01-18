package com.learn.api_gateway.util;

import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import com.learn.api_gateway.config.properties.InternalJwtProperties;

import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class InternalJwtKeyProvider {
	private final Map<String, SecretKey> keys;
    private final String activeKid;

    public InternalJwtKeyProvider(InternalJwtProperties internalJwtProperties) {

        this.keys = internalJwtProperties.getKeys().entrySet().stream()
                .collect(Collectors.toUnmodifiableMap(
                        Map.Entry::getKey,
                        e -> Keys.hmacShaKeyFor(
                                Base64.getDecoder().decode(e.getValue()))
                ));
        
        this.activeKid = internalJwtProperties.getActiveKeyId();

        if (!keys.containsKey(activeKid)) {
            throw new IllegalStateException("Active internal JWT key not found: " + activeKid);
        }

        log.info("Internal JWT keys loaded={}, activeKid={}", keys.keySet(), activeKid);
    }

    /** ACTIVE SIGNING KEY */
    public SigningKey activeKey() {
        return new SigningKey(activeKid, keys.get(activeKid));
    }

    /** VERIFICATION KEYS */
    public SecretKey key(String kid) {
        return keys.get(kid);
    }

    public Set<String> kids() {
        return keys.keySet();
    }

    /** Immutable signing tuple */
    public record SigningKey(String kid, SecretKey key) {}
}
