package com.learn.api_gateway.filter;

import java.time.Duration;
import java.util.Map;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Sudden burst detection
 * UA switching
 * Periodic bot heartbeat
 * Multi-identity attempts from same IP
 * Note: Newly added
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class BehavioralRiskScoringFilter implements GlobalFilter, Ordered{
	
	public static final String ATTR_BEHAVIOR_RISK = "risk.behavior";

    private static final long BURST_THRESHOLD_MS = 250;
    private static final int UA_ROTATION_THRESHOLD = 3;
    private static final int MAX_REQUESTS_PER_WINDOW = 120;
    private static final Duration WINDOW = Duration.ofSeconds(60);

    private final Cache<String, BehaviorState> cache =
            Caffeine.newBuilder()
                    .expireAfterAccess(Duration.ofMinutes(15))
                    .maximumSize(300_000)
                    .recordStats()
                    .build();

    @Override
    public int getOrder() {
        return -742; // after fingerprint, before captcha
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String ip = (String) exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP);
        String fingerprint = (String) exchange.getAttribute(
                UserAgentValidationAndFingerprintFilter.ATTR_CLIENT_FINGERPRINT
        );
        
        log.info("------------BehavioralRiskScoringFilter is running for ip {}, fingerprint {}--------", ip, fingerprint);
        
        if (ip == null || fingerprint == null) {
            return chain.filter(exchange);
        }

        String key = ip + "|" + fingerprint;
        long now = System.currentTimeMillis();

        BehaviorState state = cache.get(key, k -> new BehaviorState(now));
        
        int risk = 0;
        /* ===============================
         * 1.Burst detection (micro-burst)
         * =============================== */
        long delta = now - state.lastRequestTs;
        if (delta > 0 && delta < BURST_THRESHOLD_MS) {
            risk += 15;
        }

        /* ===============================
         * 2.Sliding window rate anomaly
         * =============================== */
        if (now - state.windowStartTs > WINDOW.toMillis()) {
            state.resetWindow(now);
        }

        state.requestsInWindow++;

        if (state.requestsInWindow > MAX_REQUESTS_PER_WINDOW) {
            risk += 20;
        }

        /* ===============================
         * 3.User-Agent rotation
         * =============================== */
        String ua = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.USER_AGENT);

        if (ua != null && !ua.equals(state.lastUserAgent)) {
            state.uaRotationCount++;
            if (state.uaRotationCount >= UA_ROTATION_THRESHOLD) {
                risk += 15;
            }
        }

        /* ===============================
         * 4.Periodicity detection (bot heartbeat)
         * =============================== */
        if (state.lastInterval > 0) {
            long jitter = Math.abs(delta - state.lastInterval);
            if (jitter < 30) { // very stable cadence
                risk += 10;
            }
        }

        /* ===============================
         * 5.Progressive decay
         * =============================== */
        state.lastInterval = delta;
        state.lastRequestTs = now;
        state.lastUserAgent = ua;

        if (risk > 0) {
        	log.info(
        	        "[BEHAVIOR-RISK] ip={} fp={} riskAdded={} delta={} windowCount={} uaRotations={}",
        	        ip,
        	        fingerprint,
        	        risk,
//        	        totalRisk,
        	        delta,
        	        state.requestsInWindow,
        	        state.uaRotationCount
        	    );

            Map<String, Object> attrs = exchange.getAttributes();

            Integer existing =
                    attrs.get(ATTR_BEHAVIOR_RISK) instanceof Integer i ? i : 0;

            int totalRisk = Math.min(existing + risk, 100); // clamp

            attrs.put(ATTR_BEHAVIOR_RISK, totalRisk);

            if (log.isDebugEnabled()) {
                log.debug(
                        "[BehaviorRisk] ip={} fingerprint={} riskAdded={} totalRisk={} windowCount={} uaRotations={}",
                        ip,
                        fingerprint,
                        risk,
                        totalRisk,
                        state.requestsInWindow,
                        state.uaRotationCount
                );
            }
        }
        return chain.filter(exchange);
    }

    /* ===============================
     * INTERNAL STATE (immutable rules)
     * =============================== */
    static final class BehaviorState {

        long windowStartTs;
        long lastRequestTs;
        long lastInterval;

        int requestsInWindow;
        int uaRotationCount;

        String lastUserAgent;

        BehaviorState(long now) {
            this.windowStartTs = now;
            this.lastRequestTs = now;
        }

        void resetWindow(long now) {
            this.windowStartTs = now;
            this.requestsInWindow = 0;
            this.uaRotationCount = 0;
        }
    }
}
