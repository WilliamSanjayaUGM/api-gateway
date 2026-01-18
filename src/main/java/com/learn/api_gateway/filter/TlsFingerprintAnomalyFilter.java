package com.learn.api_gateway.filter;

import java.util.ArrayList;
import java.util.List;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import com.learn.api_gateway.config.properties.TlsFingerprintProperties;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * JA3 + JA4 heuristic scoring
 * Detects:
 * Playwright / Puppeteer
 * curl spoofing Chrome UA
 * TLS downgrade patterns
 * Impossible cipher/extension combos
 * The filter never blocks.
 * Downstream filters decide what to do with risk.
 * Note: newly added
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class TlsFingerprintAnomalyFilter implements GlobalFilter, Ordered{
	
	private static final int MAX_RISK_PER_FILTER = 100;
    private static final int MAX_FP_LENGTH = 256;

    private final TlsFingerprintProperties props;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        HttpHeaders headers = exchange.getRequest().getHeaders();

        String ja3 = sanitizeFingerprint(headers.getFirst("X-JA3-Fingerprint"));
        String ja4 = sanitizeFingerprint(headers.getFirst("X-JA4-Fingerprint"));
        String ua  = headers.getFirst(HttpHeaders.USER_AGENT);

        String clientIp = (String) exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP);
        boolean internal = isInternalTraffic(clientIp);
        
        log.info("----------TlsFingerprintAnomalyFilter is running with clientIp {}--------", clientIp);
        
        int risk = 0;
        List<String> signals = new ArrayList<>();

        /* ===============================
         * 1) Known bad TLS fingerprints
         * =============================== */
        if (StringUtils.hasText(ja3) && props.getKnownBadJa3().contains(ja3)) {
            risk += 40;
            signals.add("KNOWN_BAD_JA3");
        }

        /* ===============================
         * 2) Impossible UA + TLS combos
         * =============================== */
        if (StringUtils.hasText(ua)
                && ua.contains("Chrome")
                && StringUtils.hasText(ja3)
                && props.getCurlLikeJa3().contains(ja3)) {

            risk += 50;
            signals.add("IMPOSSIBLE_TLS_STACK");
        }

        /* ===============================
         * 3) TLS downgrade / anomaly (JA4)
         * =============================== */
        if (StringUtils.hasText(ja4)
                && props.getDowngradePatterns().stream().anyMatch(ja4::contains)) {

            risk += 30;
            signals.add("TLS_DOWNGRADE_PATTERN");
        }

        /* ===============================
         * 4) Missing fingerprint in strict zones
         * =============================== */
        if (internal && !StringUtils.hasText(ja3)) {
            risk += 25;
            signals.add("MISSING_JA3_INTERNAL");
        }

        /* ===============================
         * 5) Bound & aggregate risk
         * =============================== */
        if (risk > 0) {
            int bounded = Math.min(risk, MAX_RISK_PER_FILTER);

            exchange.getAttributes().merge(
                    "risk.tls",
                    bounded,
                    (oldVal, newVal) -> Math.min(
                            MAX_RISK_PER_FILTER,
                            ((Integer) oldVal) + ((Integer) newVal))
            );

            exchange.getAttributes().put("risk.tls.signals", signals);

            log.warn(
                "[TLS-RISK] ip={} internal={} risk={} signals={} ja3={} ja4={}",
                clientIp,
                internal,
                bounded,
                signals,
                abbreviate(ja3),
                abbreviate(ja4)
            );
        }

        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return -745;
    }

    /* ===============================
     * Helpers
     * =============================== */

    private String sanitizeFingerprint(String fp) {
        if (!StringUtils.hasText(fp)) return null;
        if (fp.length() > MAX_FP_LENGTH) return null;
        if (!fp.matches("^[a-zA-Z0-9:_\\-\\.]+$")) return null;
        return fp;
    }

    private String abbreviate(String fp) {
        if (fp == null) return "null";
        return fp.length() > 32 ? fp.substring(0, 32) + "…" : fp;
    }

    private boolean isInternalTraffic(String ip) {
        if (!StringUtils.hasText(ip)) return false;
        return ip.startsWith("10.")
            || ip.startsWith("192.168.")
            || ip.startsWith("172.16.")
            || ip.startsWith("172.17.")
            || ip.startsWith("172.18.")
            || ip.startsWith("172.19.")
            || ip.startsWith("172.20.")
            || ip.startsWith("172.21.")
            || ip.startsWith("172.22.")
            || ip.startsWith("172.23.")
            || ip.startsWith("172.24.")
            || ip.startsWith("172.25.")
            || ip.startsWith("172.26.")
            || ip.startsWith("172.27.")
            || ip.startsWith("172.28.")
            || ip.startsWith("172.29.")
            || ip.startsWith("172.30.")
            || ip.startsWith("172.31.");
    }

}
