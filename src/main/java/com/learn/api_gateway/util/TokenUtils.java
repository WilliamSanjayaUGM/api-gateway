package com.learn.api_gateway.util;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import lombok.experimental.UtilityClass;

@UtilityClass
public class TokenUtils {
	private static final Logger log = LoggerFactory.getLogger(TokenUtils.class);

    /**
     * Calculate TTL from "exp" claim in token attributes.
     */
    public Duration ttlFromExp(Map<String, Object> attrs, Duration fallback, Duration clockSkew) {
    	Object exp = attrs.get("exp");
        if (exp == null) return fallback;

        try {
            Instant expInstant;

            if (exp instanceof Instant instant) {
                expInstant = instant;
            } else if (exp instanceof Number num) {
                expInstant = Instant.ofEpochSecond(num.longValue());
            } else if (exp instanceof String str) {
                expInstant = Instant.parse(str); //ISO-8601 SAFE
            } else {
                log.warn("Unsupported exp claim type: {}", exp.getClass().getName());
                return fallback;
            }

            Duration ttl = Duration.between(Instant.now(), expInstant).minus(clockSkew);
            return (ttl.isNegative() || ttl.isZero()) ? Duration.ZERO : ttl;

        } catch (Exception e) {
            log.warn("Unable to parse 'exp' claim, falling back to default TTL: {}", exp, e);
            return fallback;
        }
    }
}
