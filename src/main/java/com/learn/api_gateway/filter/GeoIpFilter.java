package com.learn.api_gateway.filter;

import java.net.InetAddress;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import com.learn.api_gateway.config.properties.TrustProperties;
import com.learn.api_gateway.service.GeoIpService;
import com.learn.api_gateway.util.EdgeIpCanonicalizer;
import com.learn.api_gateway.util.ErrorResponseWriter;
import com.learn.api_gateway.util.ReactorMdc;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/*
 * Detect IP, Lookup country, Optionally reject blocket countries or pass it via header to microservices
 */
@Slf4j
@Component
@Order(-800)
@RequiredArgsConstructor
public class GeoIpFilter implements WebFilter{
	
	private final GeoIpService geoIpService;
    private final MeterRegistry meterRegistry;
    private final ErrorResponseWriter errorResponseWriter;
    private final EdgeIpCanonicalizer ipCanon;

    @Value("${geoip.whitelist.countries:}")
    private String whitelistCountries;

    private Set<String> whitelistSet = Collections.emptySet();
    private Counter blockedCounter;
    private Counter unknownCounter;
    
    @Value("${geoip.fail-fast:false}")
    private boolean failFast;

    @PostConstruct
    void init() {
    	if (!whitelistCountries.isBlank()) {
            whitelistSet = Arrays.stream(whitelistCountries.split(","))
                    .map(String::trim)
                    .map(String::toUpperCase)
                    .collect(Collectors.toSet());
        }
        blockedCounter = Counter.builder("geoip.blocked.filter").register(meterRegistry);
        unknownCounter = Counter.builder("geoip.unknown.filter").register(meterRegistry);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String ip = exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP);
        if (ip == null || ip.isBlank()) {
            unknownCounter.increment();
            return forwardWithCountry(exchange, chain, "UNKNOWN");
        }
        
        if (isNonRoutable(ip)) {
            log.debug("Skipping GeoIP for non-routable/internal IP={}", ip);
            return forwardWithCountry(exchange, chain, "INTERNAL");
        }
        log.info("------------GeoIpFilter is checked ip:{}--------",ip);
        // Add resilience timeout & graceful fallback
        return geoIpService.evaluate(ip, whitelistSet)
                .timeout(Duration.ofSeconds(2))
                .onErrorResume(ex -> {
                    log.warn("GeoIP evaluation error: {}", ex.getMessage());
                    unknownCounter.increment();
                    return Mono.just(new GeoIpService.CountryDecision("UNKNOWN", false, false, true));
                })
                .flatMap(decision -> {
                    if (decision.unknown()) {
                    	unknownCounter.increment();

                        if (failFast) {
                            log.error("FAIL-CLOSED: Blocking UNKNOWN GeoIP for ip={}", ip);
                            return errorResponseWriter.write(
                                    exchange,
                                    HttpStatus.FORBIDDEN,
                                    "Access denied (GeoIP resolution failed)"
                            );
                        }

                        return forwardWithCountry(exchange, chain, "UNKNOWN"); // DEV fallback only
                    }

                    if (decision.blocked() && !decision.whitelisted()) {
                        blockedCounter.increment();
                        log.warn("Blocked IP={} country={}", ip, decision.country());
                        return errorResponseWriter.write(
                                exchange,
                                HttpStatus.FORBIDDEN,
                                "Access denied from country: " + decision.country());
                    }
                    
                    return forwardWithCountry(exchange, chain, decision.country());
                })
                .transformDeferred(ReactorMdc.mdcOperatorVoid());
    }
    
    private Mono<Void> forwardWithCountry(ServerWebExchange exchange, WebFilterChain chain, String country) {
        ServerHttpRequest req = exchange.getRequest().mutate()
                .header("X-Country-Code", country)
                .build();
        return chain.filter(exchange.mutate().request(req).build());
    }
    
    private boolean isNonRoutable(String ip) {
        InetAddress addr = ipCanon.parse(ip);
        return ipCanon.isNonRoutable(addr);
    }
}
