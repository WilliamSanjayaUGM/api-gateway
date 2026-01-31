package com.learn.api_gateway.filter;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.scope.refresh.RefreshScopeRefreshedEvent;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.event.EventListener;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.learn.api_gateway.config.properties.TrustProperties;
import com.learn.api_gateway.util.EdgeIpCanonicalizer;
import com.learn.api_gateway.util.ReactorMdc;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@Order(-850)
@RequiredArgsConstructor
public class ClientIpFilter implements WebFilter{
    private final TrustProperties trustProperties;

    public static final String ATTR_CLIENT_IP = "clientIp";

    @Value("${gateway.forwarded-for.strategy:leftmost}") // "leftmost" or "rightmost"
    private String forwardedForStrategy;

    @Value("${gateway.headers.set-x-real-ip:true}")
    private boolean setXRealIp;
    
    @Value("${gateway.strip-xff:false}")
    private boolean stripXForwardedFor;

    @Value("${gateway.max-xff-hops:16}")
    private int maxXffHops;
    
    private final EdgeIpCanonicalizer ipCanon;
    
    // Caffeine cache for trusted IP decisions
    private final Cache<String, Boolean> trustCache = Caffeine.newBuilder()
            .maximumSize(50_000)
            .expireAfterWrite(Duration.ofHours(1))
            .recordStats()
            .build();
    
    private final Map<String, Long> lastUntrustedLog = new ConcurrentHashMap<>();
    private static final long UNTRUSTED_LOG_INTERVAL_MS = 60_000; // 1 minute

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    	String cachedIp = (String) exchange.getAttribute(ATTR_CLIENT_IP);
        if (cachedIp != null) {
            return chain.filter(exchange);
        }

        String clientIp = resolveClientIp(exchange);
        exchange.getAttributes().put(ATTR_CLIENT_IP, clientIp);

        ServerHttpRequest mutated = exchange.getRequest().mutate()
                .headers(headers -> {
                    headers.set("X-Client-IP", clientIp);
                    if (setXRealIp) headers.set("X-Real-IP", clientIp);

                    if (stripXForwardedFor) {
                        headers.remove("X-Forwarded-For");
                    }
                })
                .build();
        
        log.info("------------ClientIpFilter is passed--------");
        return chain.filter(exchange.mutate().request(mutated).build())
                .transformDeferred(ReactorMdc.mdcOperatorVoid());
    }
    
    // Core unified resolver logic
    private String resolveClientIp(ServerWebExchange exchange) {
        HttpHeaders headers = exchange.getRequest().getHeaders();
        String remoteIp = resolveRemoteAddress(exchange);

        boolean proxyTrusted = isTrusted(remoteIp);
        
        log.warn("----ClientIpFilter resolveClientIp → X-Forwarded-For = {}, remoteIp {}, proxyTrusted {}----", 
        		headers.getFirst("X-Forwarded-For"), remoteIp, proxyTrusted);
        
        // If proxy is NOT trusted → IGNORE XFF COMPLETELY
        if (!proxyTrusted) {
            maybeLogUntrusted(remoteIp, headers.getFirst("X-Forwarded-For"));
            return remoteIp;
        }

        // Only trusted proxies may supply XFF
        String xff = headers.getFirst("X-Forwarded-For");
        if (xff == null || xff.isBlank()) {
            return remoteIp;
        }

        String[] chain = Arrays.stream(xff.split(","))
                .map(String::trim)
                .map(ipCanon::parse)
                .filter(Objects::nonNull)
                .map(ipCanon::canonical)
                .limit(maxXffHops)
                .toArray(String[]::new);

        if (chain.length == 0) return remoteIp;

        return "rightmost".equalsIgnoreCase(forwardedForStrategy)
                ? chain[chain.length - 1]    // last untrusted hop
                : chain[0];                  // original client
    }
    
    private String resolveRemoteAddress(ServerWebExchange exchange) {
        InetSocketAddress ra = exchange.getRequest().getRemoteAddress();
        if (ra == null || ra.getAddress() == null) {
            return "unknown";
        }
        return ipCanon.canonical(ra.getAddress());
    }

    private boolean isTrusted(String ip) {
        return trustCache.get(ip, k->{
        	InetAddress addr = ipCanon.parse(k);
        	return addr!=null && trustProperties.isTrusted(addr);
        });
    }

    private void maybeLogUntrusted(String remoteIp, String xff) {
    	InetAddress addr = ipCanon.parse(remoteIp);
        String canonicalIp = ipCanon.canonical(addr);

        // Use canonical IP for rate limiting logs
        long now = System.currentTimeMillis();
        Long last = lastUntrustedLog.get(canonicalIp);

        if (last != null && (now - last) <= UNTRUSTED_LOG_INTERVAL_MS) {
            return;
        }

        lastUntrustedLog.put(canonicalIp, now);

        log.warn(
            "SECURITY: Untrusted proxy hop detected — " +
            "remoteIp={} xffPresent={} reason=PROXY_NOT_TRUSTED",
            maskForLog(canonicalIp),
            (xff != null && !xff.isBlank())
        );
    }
    
    private String maskForLog(String ip) {
        if (ip == null) return "unknown";

        if (ip.contains(".")) { // IPv4
            int idx = ip.lastIndexOf('.');
            return (idx > 0) ? ip.substring(0, idx) + ".x" : "x.x.x.x";
        }

        if (ip.contains(":")) { // IPv6
            return ip.replaceAll(":[0-9a-fA-F]{1,4}", ":x");
        }

        return "unknown";
    }
    
    @EventListener(RefreshScopeRefreshedEvent.class)
    public void onConfigRefresh() {
        log.info("Clearing trust cache after TrustProperties refresh");
        trustCache.invalidateAll();
    }
}
