package com.learn.api_gateway.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import com.learn.api_gateway.config.properties.UserAgentFingerprintProperties;
import com.learn.api_gateway.resolver.ClientTypeResolver;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

@Slf4j
@Component
@RequiredArgsConstructor
public class UserAgentValidationAndFingerprintFilter implements GlobalFilter, Ordered {

    public static final String ATTR_CLIENT_FINGERPRINT = "security.clientFingerprint";
    public static final String HEADER_DEVICE_ID = "X-Device-Id"; // optional custom header
    public static final String HEADER_TRACE_ID = "X-Trace-Id";   // align with your logging filter

    private final UserAgentFingerprintProperties properties;
    private volatile List<Pattern> blockedPatterns;
    private volatile List<Pattern> allowedPatterns;
    private final ClientTypeResolver clientTypeResolver;

    @Override
    public int getOrder() {
        return -780;
    }

    private List<Pattern> getBlockedPatterns() {
        if (blockedPatterns == null) {
            blockedPatterns = properties.getBlockedPatterns().stream()
                    .filter(StringUtils::hasText)
                    .map(p -> Pattern.compile(p, Pattern.CASE_INSENSITIVE))
                    .collect(Collectors.toUnmodifiableList());
        }
        return blockedPatterns;
    }

    private List<Pattern> getAllowedPatterns() {
        if (allowedPatterns == null) {
            allowedPatterns = properties.getAllowedPatterns().stream()
                    .filter(StringUtils::hasText)
                    .map(p -> Pattern.compile(p, Pattern.CASE_INSENSITIVE))
                    .collect(Collectors.toUnmodifiableList());
        }
        return allowedPatterns;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {
    	if (!properties.isEnabled()) {
            return chain.filter(exchange);
        }

        ServerHttpRequest request = exchange.getRequest();
        HttpHeaders headers = request.getHeaders();

        String traceId = headers.getFirst(HEADER_TRACE_ID);
        String userAgent = headers.getFirst(HttpHeaders.USER_AGENT);
        String accept = headers.getFirst(HttpHeaders.ACCEPT);
        String acceptLanguage = headers.getFirst(HttpHeaders.ACCEPT_LANGUAGE);
        String deviceId = headers.getFirst(HEADER_DEVICE_ID);
        String clientIp = resolveClientIp(exchange);
        
        log.info("----------UserAgentValidationAndFingerprintFilter is running with traceId {}, userAgent {}, deviceId {}, clientIp {}",
        		traceId, userAgent,deviceId, clientIp);
        
        // Optional JA3 from nginx / ingress / WAF
        String ja3HeaderName = properties.getJa3HeaderName();
        String ja3 = StringUtils.hasText(ja3HeaderName)
                ? headers.getFirst(ja3HeaderName)
                : null;

        // 1) JA3 presence / allow-list
        if (isStrictJa3Required(exchange,clientIp)) {

            // STRICT MODE: internal / private / m2m
            if (!StringUtils.hasText(ja3)) {
                log.warn("[traceId={}] Blocking request without JA3 in STRICT mode from IP={}",
                        traceId, clientIp);
                return block(exchange, HttpStatus.FORBIDDEN);
            }

            if (!properties.getAllowedJa3Fingerprints().isEmpty()
                    && !properties.getAllowedJa3Fingerprints().contains(ja3)) {
                log.warn("[traceId={}] Blocking request with untrusted JA3={} in STRICT mode from IP={}",
                        traceId, ja3, clientIp);
                return block(exchange, HttpStatus.FORBIDDEN);
            }

        } else {

            // SOFT MODE: public browser traffic
            if (StringUtils.hasText(ja3)
                    && !properties.getAllowedJa3Fingerprints().isEmpty()
                    && !properties.getAllowedJa3Fingerprints().contains(ja3)) {

                // ⚠️ SIGNAL ONLY — DO NOT BLOCK
                log.warn("[traceId={}] Suspicious JA3={} for public traffic from IP={} (not blocking)",
                        traceId, ja3, clientIp);

                // Optional: mark for downstream risk-based decisions
                exchange.getAttributes().put("risk.ja3.suspicious", true);
            }
        }

        // 2) User-Agent presence & baseline validation
        if (!StringUtils.hasText(userAgent)) {
            if (!isInternalTraffic(clientIp) || !properties.isAllowEmptyForInternal()) {
                log.warn("[traceId={}] Blocking request with missing User-Agent from IP={}", traceId, clientIp);
                return block(exchange, HttpStatus.BAD_REQUEST);
            }
            // internal with empty UA allowed, continue; still fingerprint on IP/device-id/etc.
        } else {
            if (!validateUserAgent(userAgent, traceId, clientIp)) {
                return block(exchange, HttpStatus.FORBIDDEN);
            }

            // 3) Optional UA vs Accept / Accept-Language consistency check
            if (properties.isEnableUaConsistencyCheck()) {
                boolean consistent = isUaHeaderCombinationPlausible(
                        userAgent, accept, acceptLanguage, traceId, clientIp);

                if (!consistent && properties.isBlockOnUaInconsistency()) {
                    return block(exchange, HttpStatus.FORBIDDEN);
                }
            }
        }

        // 4) Build a "header shape" fingerprint (header names + multiplicity)
        String headerShape = buildHeaderShape(headers);

        String fingerprint = generateFingerprint(
                clientIp,
                userAgent,
                acceptLanguage,
                deviceId,
                ja3,
                headerShape
        );

        ServerHttpRequest mutatedRequest = request.mutate()
                .header(properties.getFingerprintHeaderName(), fingerprint)
                .build();

        exchange.getAttributes().put(ATTR_CLIENT_FINGERPRINT, fingerprint);

        if (log.isDebugEnabled()) {
            log.debug("[traceId={}] Resolved client fingerprint={} for IP={} ja3={}",
                    traceId, fingerprint, clientIp, ja3);
        }

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private String resolveClientIp(ServerWebExchange exchange) {
    	// Prefer trusted IP set by ClientIpFilter
        String ip = (String) exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP);
        if (StringUtils.hasText(ip)) {
            return ip;
        }

        // Fallback only if no attribute (e.g. in tests)
        HttpHeaders headers = exchange.getRequest().getHeaders();
        String xff = headers.getFirst("X-Forwarded-For");
        if (StringUtils.hasText(xff)) {
            return xff.split(",")[0].trim();
        }

        InetSocketAddress remoteAddress = exchange.getRequest().getRemoteAddress();
        return remoteAddress != null ? remoteAddress.getAddress().getHostAddress() : "unknown";
    }
    
    private String buildHeaderShape(HttpHeaders headers) {
        // e.g. "accept:1;accept-encoding:1;accept-language:1;host:1;user-agent:1;x-forwarded-for:1"
        return headers.entrySet().stream()
                .map(e -> e.getKey().toLowerCase(Locale.ROOT) + ":" + e.getValue().size())
                .sorted()  // order-insensitive but deterministic
                .collect(Collectors.joining(";"));
    }

    private boolean isInternalTraffic(String ip) {
        if (!StringUtils.hasText(ip) || "unknown".equals(ip)) {
            return false;
        }
        // Simplistic: adapt with proper CIDR checks (10/8, 172.16/12, 192.168/16, etc.)
        return ip.startsWith("10.") ||
                ip.startsWith("192.168.") ||
                ip.startsWith("172.16.") ||
                ip.startsWith("172.17.") ||
                ip.startsWith("172.18.") ||
                ip.startsWith("172.19.") ||
                ip.startsWith("172.20.") ||
                ip.startsWith("172.21.") ||
                ip.startsWith("172.22.") ||
                ip.startsWith("172.23.") ||
                ip.startsWith("172.24.") ||
                ip.startsWith("172.25.") ||
                ip.startsWith("172.26.") ||
                ip.startsWith("172.27.") ||
                ip.startsWith("172.28.") ||
                ip.startsWith("172.29.") ||
                ip.startsWith("172.30.") ||
                ip.startsWith("172.31.");
    }

    private boolean validateUserAgent(String userAgent, String traceId, String clientIp) {
        int len = userAgent.length();
        if (len < properties.getMinLength() || len > properties.getMaxLength()) {
            log.warn("[traceId={}] Blocking UA length={} out of allowed range [{}, {}] from IP={}",
                    traceId, len, properties.getMinLength(), properties.getMaxLength(), clientIp);
            return false;
        }

        // Reject control chars other than tab/newline
        for (char c : userAgent.toCharArray()) {
            if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
                log.warn("[traceId={}] Blocking UA with control characters from IP={}", traceId, clientIp);
                return false;
            }
        }

        // Optional: too many distinct characters -> probably obfuscated / random
        if (properties.getMaxDistinctChars() > 0) {
            long distinct = userAgent.chars().distinct().count();
            if (distinct > properties.getMaxDistinctChars()) {
                log.warn("[traceId={}] Blocking UA with distinctChars={} > maxDistinctChars={} from IP={}",
                        traceId, distinct, properties.getMaxDistinctChars(), clientIp);
                return false;
            }
        }

        // Block-list patterns
        for (Pattern p : getBlockedPatterns()) {
            if (p.matcher(userAgent).find()) {
                log.warn("[traceId={}] Blocking UA='{}' matching blocked pattern='{}' from IP={}",
                        traceId, safeLogUserAgent(userAgent), p.pattern(), clientIp);
                return false;
            }
        }

        // Allow-list patterns (if configured)
        List<Pattern> allowPatterns = getAllowedPatterns();
        if (!allowPatterns.isEmpty()) {
            boolean match = allowPatterns.stream().anyMatch(p -> p.matcher(userAgent).find());
            if (!match) {
                log.warn("[traceId={}] Blocking UA='{}' (no allow-list match) from IP={}",
                        traceId, safeLogUserAgent(userAgent), clientIp);
                return false;
            }
        }

        return true;
    }

    private String safeLogUserAgent(String userAgent) {
        // Trim and mask extremely long UAs in logs to prevent log injection / bloating.
        if (userAgent == null) {
            return "null";
        }
        String trimmed = userAgent.replaceAll("[\\r\\n]", " ");
        if (trimmed.length() > 200) {
            return trimmed.substring(0, 200) + "...(truncated)";
        }
        return trimmed;
    }

    private String generateFingerprint(String ip,
                                       String userAgent,
                                       String acceptLanguage,
                                       String deviceId,
                                       String ja3,
                                       String headerShape) {
    	String ua = userAgent != null ? userAgent : "";
        String lang = acceptLanguage != null ? acceptLanguage : "";
        String dev = deviceId != null ? deviceId : "";
        String ja3Val = ja3 != null ? ja3 : "";
        String shape = headerShape != null ? headerShape : "";

        // Stable canonical string
        String canonical = String.join("|",
                Optional.ofNullable(ip).orElse(""),
                ua,
                lang,
                dev,
                ja3Val,
                shape
        );

        String secret = properties.getFingerprintHmacSecret();

        if (!StringUtils.hasText(secret)) {
            log.error("Fingerprint HMAC secret is missing – refusing to generate fingerprint");
            return "fingerprint-unavailable";
        }

        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec =
                    new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");

            mac.init(keySpec);

            byte[] hash = mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8));

            // URL-safe, compact
            return Base64.encodeBase64URLSafeString(hash);

        } catch (GeneralSecurityException ex) {
            // Hard fail-safe: deterministic fallback, but VERY LOUD
            log.error("HMAC fingerprint generation failed – falling back to raw SHA-256", ex);

            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(canonical.getBytes(StandardCharsets.UTF_8));
                return Base64.encodeBase64URLSafeString(hash);
            } catch (Exception e2) {
                log.error("Fallback fingerprint generation failed", e2);
                return "fingerprint-unavailable";
            }
        }
    }
    
    private boolean isUaHeaderCombinationPlausible(String userAgent,
		            @Nullable String accept,
		            @Nullable String acceptLanguage,
		            String traceId,
		            String clientIp) {
		String uaLower = userAgent.toLowerCase(Locale.ROOT);
		String acceptVal = accept != null ? accept.toLowerCase(Locale.ROOT) : "";
		String langVal = acceptLanguage != null ? acceptLanguage.toLowerCase(Locale.ROOT) : "";
		
		boolean looksLikeBrowser =
		uaLower.contains("mozilla/5.0") ||
		uaLower.contains("chrome/") ||
		uaLower.contains("safari/") ||
		uaLower.contains("firefox/") ||
		uaLower.contains("edg/");
		
		if (!looksLikeBrowser) {
			// Could be mobile app / API client, don't be strict here
			return true;
		}
		
		// 1) Browser UA but no Accept header at all -> suspicious
		if (!StringUtils.hasText(acceptVal)) {
			log.warn("[traceId={}] Suspicious: browser-like UA but missing Accept header from IP={}",
			traceId, clientIp);
			return false;
		}
		
		// 2) Browser UA but Accept is extremely generic and nothing else
		//    (many bots do 'Accept: */*' only)
		if ("*/*".equals(acceptVal.trim())) {
			log.warn("[traceId={}] Suspicious: browser-like UA with bare '*/*' Accept from IP={}",
			traceId, clientIp);
			return false;
		}
		
		// 3) Browser UA but no Accept-Language -> not always wrong, but unusual for real browsers
		if (!StringUtils.hasText(langVal)) {
			log.warn("[traceId={}] Suspicious: browser-like UA but missing Accept-Language from IP={}",
			traceId, clientIp);
			return false;
		}
		
		// Basic sanity: language code should not be pure garbage
		if (langVal.length() < 2 || langVal.length() > 32) {
			log.warn("[traceId={}] Suspicious: weird Accept-Language='{}' for browser-like UA from IP={}",
			traceId, acceptLanguage, clientIp);
			return false;
		}
		
		return true;
	}

    private Mono<Void> block(ServerWebExchange exchange, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().set(HttpHeaders.CONTENT_TYPE, "application/json");

        String body = """
                {
                  "timestamp": "%s",
                  "status": %d,
                  "error": "Request blocked by security policy",
                  "message": "Your request was blocked by the User-Agent security policy.",
                  "path": "%s"
                }
                """.formatted(
                new Date(),
                status.value(),
                exchange.getRequest().getPath().value()
        );

        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        return response.writeWith(Mono.just(response.bufferFactory().wrap(bytes)));
    }
    
    private boolean isStrictJa3Required(ServerWebExchange exchange,String clientIp) {
    	ClientTypeResolver.ClientType clientType =
                clientTypeResolver.resolve(exchange);

        // NEVER require JA3 for mobile apps
        if (clientType == ClientTypeResolver.ClientType.MOBILE) {
            return false;
        }

        // NEVER require JA3 for browsers
        if (clientType == ClientTypeResolver.ClientType.BROWSER) {
            return false;
        }

        // Require JA3 ONLY for machine-to-machine APIs
        if (clientType == ClientTypeResolver.ClientType.API) {
            return properties.isRequireJa3ForPrivateApis();
        }

        return false;
    }
}
