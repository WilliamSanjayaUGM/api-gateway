package com.learn.api_gateway.filter;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.learn.api_gateway.util.WAFBootstrapUtil;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Newly added
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class ApiScrapingDefenseFilter implements GlobalFilter,Ordered {

	public static final String ATTR_SCRAPING_RISK = "risk.scraping";

    private static final int MAX_REQUESTS_PER_MINUTE = 120;
    private static final int SEQUENTIAL_THRESHOLD = 15;
    private static final int MAX_RISK = 100;

    // Conviction & blocking
    private static final int SCRAPING_CONVICTION_THRESHOLD = 3;
    private static final Duration STRIKE_TTL = Duration.ofMinutes(30);
    private static final Duration BLOCK_TTL = Duration.ofMinutes(15);

    private static final List<String> SCRAPE_PATH_PREFIXES = List.of(
    		"/v1/product/test",
    	    "/product-detail/test"
    );

    private final Cache<String, ScrapeState> cache =
            Caffeine.newBuilder()
                    .expireAfterAccess(Duration.ofMinutes(5))
                    .maximumSize(200_000)
                    .build();

    // Redis for conviction + blocking
    private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
    private final WAFBootstrapUtil wafBootstrapUtil;

    @Override
    public int getOrder() {
        return -760;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String path = exchange.getRequest().getPath().value();
        log.info("------------ApiScrapingDefenseFilter is running for path {}--------", path);
        
        if (!isScrapeRelevantPath(path)) {
            return chain.filter(exchange);
        }

        String fingerprint = (String) exchange.getAttribute(
                UserAgentValidationAndFingerprintFilter.ATTR_CLIENT_FINGERPRINT
        );
        String ip = (String) exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP);

        if (fingerprint == null || ip == null) {
            return chain.filter(exchange);
        }

        String identity = ip + "|" + fingerprint;
        String blockKey = "scrape:block:" + identity;
        String strikeKey = "scrape:strike:" + identity;

        /* ===============================
         * ★ 0. HARD BLOCK CHECK
         * =============================== */
        return reactiveRedisTemplate.hasKey(blockKey)
                .flatMap(blocked -> {
                    if (Boolean.TRUE.equals(blocked)) {
                        log.warn("[Scraping] BLOCKED ip={} fp={}", ip, fingerprint);
                        return wafBootstrapUtil.block(
                                exchange,
                                HttpStatus.FORBIDDEN,
                                "Automated scraping detected"
                        );
                    }

                    return evaluateScraping(exchange, chain, identity, strikeKey);
                });
    }

    private Mono<Void> evaluateScraping(
            ServerWebExchange exchange,
            GatewayFilterChain chain,
            String identity,
            String strikeKey) {

        long now = System.currentTimeMillis();
        ScrapeState state = cache.get(identity, k -> new ScrapeState(now));

        int risk = 0;
        String path = exchange.getRequest().getPath().value();

        /* 1. Sliding window */
        if (now - state.windowStart > 60_000) {
            state.reset(now);
        }

        state.requestsInWindow++;
        if (state.requestsInWindow > MAX_REQUESTS_PER_MINUTE) {
            risk += 20;
        }

        /* 2. Sequential crawl */
        if (path.equals(state.lastPath)) {
            state.sequentialCount++;
            if (state.sequentialCount >= SEQUENTIAL_THRESHOLD) {
                risk += 20;
            }
        } else {
            state.sequentialCount = 0;
        }

        /* 3. Missing browser signals */
        HttpHeaders h = exchange.getRequest().getHeaders();
        if (h.getFirst(HttpHeaders.ACCEPT_LANGUAGE) == null) risk += 10;
        if (h.getFirst(HttpHeaders.REFERER) == null) risk += 10;

        state.lastPath = path;

        /* ===============================
         * ★ 4. STRIKE LOGIC (conviction)
         * =============================== */
        if (risk >= 40) { // strong scraping signal

            return reactiveRedisTemplate.opsForValue()
                    .increment(strikeKey)
                    .flatMap(strikes -> {
                        if (strikes == 1) {
                            reactiveRedisTemplate.expire(strikeKey, STRIKE_TTL).subscribe();
                        }

                        if (strikes >= SCRAPING_CONVICTION_THRESHOLD) {
                            log.warn("[Scraping] CONVICTED identity={} strikes={}", identity, strikes);
                            return reactiveRedisTemplate.opsForValue()
                                    .set("scrape:block:" + identity, "1", BLOCK_TTL)
                                    .then(wafBootstrapUtil.block(
                                            exchange,
                                            HttpStatus.FORBIDDEN,
                                            "Automated scraping detected"
                                    ));
                        }

                        return chain.filter(exchange);
                    });
        }

        /* ===============================
         * 5. Risk propagation (unchanged)
         * =============================== */
        if (risk > 0) {
            Map<String, Object> attrs = exchange.getAttributes();
            Integer existing = attrs.get(ATTR_SCRAPING_RISK) instanceof Integer i ? i : 0;
            attrs.put(ATTR_SCRAPING_RISK, Math.min(existing + risk, MAX_RISK));
        }

        return chain.filter(exchange);
    }

    private boolean isScrapeRelevantPath(String path) {
        return SCRAPE_PATH_PREFIXES.stream().anyMatch(path::startsWith);
    }

    static final class ScrapeState {
        long windowStart;
        int requestsInWindow;
        int sequentialCount;
        String lastPath;

        ScrapeState(long now) {
            this.windowStart = now;
        }

        void reset(long now) {
            this.windowStart = now;
            this.requestsInWindow = 0;
            this.sequentialCount = 0;
            this.lastPath = null;
        }
    }
}
