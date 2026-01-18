package com.learn.api_gateway.filter;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Base64;
import java.util.Locale;
import java.util.regex.Pattern;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import com.learn.api_gateway.util.GatewayUtil;
import com.learn.api_gateway.util.WAFBootstrapUtil;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * protects against transport-layer and protocol-layer abuse
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class RequestBodyStructuralValidationFilter implements GlobalFilter, Ordered {

	private static final Pattern JSON_POLYGLOT_PATTERN =
            Pattern.compile("[\\}\\]\\)]\\s*<\\s*script", Pattern.CASE_INSENSITIVE);

    private static final Pattern BASE64_PATTERN =
            Pattern.compile("^[A-Za-z0-9+/=\\r\\n]{24,}$");

    private static final int HIGH_RISK_THRESHOLD = 60;

    private final WAFBootstrapUtil waf;
    private final GatewayUtil gatewayUtil;
    
    @Override
	public int getOrder() {
		return -750;
	}

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        if (waf.isBootstrapPath(exchange)) {
            return chain.filter(exchange);
        }
        
        log.info("------------RequestBodyStructuralValidationFilter is checked--------");
        
        byte[] body = gatewayUtil.getCachedRequestBody(exchange);
        if (body == null || body.length == 0) {
        	log.info("------------RequestBodyStructuralValidationFilter body null--------");
            return chain.filter(exchange);
        }

        String raw = new String(body, StandardCharsets.UTF_8);
        String normalized = deeplyNormalize(raw);
        
        if (JSON_POLYGLOT_PATTERN.matcher(normalized).find()) {
        	log.warn("----JSON polyglot payload detected-------");
            return block(exchange, "JSON polyglot payload detected");
        }
        
        if (looksLikeBase64(normalized)) {
            String decoded = tryDecodeBase64(normalized);
            if (decoded != null &&
                JSON_POLYGLOT_PATTERN
                        .matcher(deeplyNormalize(decoded))
                        .find()) {

                return block(exchange, "Encoded polyglot payload detected");
            }
        }

        /* ======================================
         * SEMANTIC ATTACK SIGNALING (NO BLOCK)
         * ====================================== */
        int risk = 0;
        String lower = normalized.toLowerCase(Locale.ROOT);

        if (containsSqlLikePatterns(lower)) risk += 30;
        if (containsXssLikePatterns(lower)) risk += 30;
        if (containsSsrfLikePatterns(lower)) risk += 40;

        if (risk > 0) {
            exchange.getAttributes().merge(
                    "risk.semantic",
                    risk,
                    (a, b) -> Math.min(100, (Integer) a + (Integer) b)
            );

            log.warn(
                "[RISK] semantic payload patterns detected path={} risk={}",
                exchange.getRequest().getPath(),
                risk
            );
        }

        /* ==================================================
         * ENDPOINT-AWARE ENFORCEMENT (SAFE HARD BLOCK)
         * ================================================== */
        if (risk >= HIGH_RISK_THRESHOLD && isUnauthenticated(exchange)) {
            return block(
                    exchange,
                    "High-risk payload on unauthenticated endpoint"
            );
        }
        log.info("------------RequestBodyStructuralValidationFilter is pass--------");
        return chain.filter(exchange);
    }

    /* ===============================
     * Semantic RISK helpers
     * =============================== */

    private boolean containsSqlLikePatterns(String s) {
        return s.contains("select ")
            || s.contains(" union ")
            || s.contains(" or 1=1");
    }

    private boolean containsXssLikePatterns(String s) {
        return s.contains("<script")
            || s.contains("javascript:");
    }

    private boolean containsSsrfLikePatterns(String s) {
        return s.contains("169.254.169.254")
            || s.contains("localhost");
    }

    /* ===============================
     * Helpers
     * =============================== */

    private boolean isUnauthenticated(ServerWebExchange exchange) {
        return exchange.getPrincipal() == null;
    }

    private String deeplyNormalize(String input) {
        String out = input;
        for (int i = 0; i < 3; i++) {
            out = safeUrlDecode(out);
        }
        out = Normalizer.normalize(out, Normalizer.Form.NFKC);
        out = out.replace("\u0000", "");
        return out;
    }

    private String safeUrlDecode(String input) {
        try {
            return URLDecoder.decode(input, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return input;
        }
    }

    private boolean looksLikeBase64(String input) {
        return input.length() >= 24 &&
               BASE64_PATTERN.matcher(input.trim()).matches();
    }

    private String tryDecodeBase64(String input) {
        try {
            return new String(
                    Base64.getDecoder().decode(input.trim()),
                    StandardCharsets.UTF_8
            );
        } catch (Exception e) {
            return null;
        }
    }

    private Mono<Void> block(ServerWebExchange exchange, String reason) {
    	log.info("-----------it goes to block RequestBodyStructuralValidationFilter---");
        exchange.getAttributes().put(
                WAFBootstrapUtil.ATTR_WAF_BLOCKED, true
        );
        return waf.block(exchange, HttpStatus.BAD_REQUEST, reason);
    }
}
