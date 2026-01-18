package com.learn.api_gateway.service;

import java.io.InputStream;
import java.net.InetAddress;
import java.time.Duration;
import java.util.Set;

import org.springframework.core.io.ResourceLoader;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.learn.api_gateway.config.properties.GeoIpProperties;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.model.CountryResponse;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

@Slf4j
@Service
@RequiredArgsConstructor
public class GeoIpService {

	private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
    private final GeoIpProperties geoIPProps;
    private final MeterRegistry meterRegistry;
    private final ResourceLoader resourceLoader;
    private DatabaseReader databaseReader;

    // Local fallback cache — avoids Redis dependency for every lookup
    private final Cache<String, String> fallbackCache = Caffeine.newBuilder()
            .maximumSize(100_000)
            .expireAfterWrite(Duration.ofHours(6))
            .recordStats()
            .build();

    private Counter hitCounter;
    private Counter missCounter;
    private Counter blockedCounter;
    private Counter errorCounter;

    @PostConstruct
    void init() {
        hitCounter = Counter.builder("geoip.lookup.hit").register(meterRegistry);
        missCounter = Counter.builder("geoip.lookup.miss").register(meterRegistry);
        blockedCounter = Counter.builder("geoip.blocked").register(meterRegistry);
        errorCounter = Counter.builder("geoip.lookup.error").register(meterRegistry);
        
        try {
            Resource resource = resourceLoader.getResource(geoIPProps.getLocalPath());

            try (InputStream is = resource.getInputStream()) {
                this.databaseReader = new DatabaseReader.Builder(is).build();
                log.info("GeoIP database loaded successfully from {}", geoIPProps.getLocalPath());
            }

        } catch (Exception e) {
            log.error("❌ CRITICAL: Failed to load GeoIP database from {}",
                    geoIPProps.getLocalPath(), e);

            if (geoIPProps.isFailFast()) {
                throw new IllegalStateException("GeoIP database not available", e);
            }
        }
    }
    
    public Mono<CountryDecision> evaluate(String ip, Set<String> whitelist) {
        return resolveCountry(ip)
                .map(country -> {
                    if ("UNKNOWN".equalsIgnoreCase(country)) {
                        return new CountryDecision(country, false, false, true);
                    }
                    boolean whitelisted = whitelist.contains(country);
                    boolean blocked = geoIPProps.getBlockedCountries().contains(country);
                    if (blocked) blockedCounter.increment();
                    return new CountryDecision(country, blocked, whitelisted, false);
                });
    }

    /**
     * Resolves country for the given IP, using Redis → local cache fallback.
     * Includes timeout and graceful degradation to "UNKNOWN".
     */
    public Mono<String> resolveCountry(String ip) {
        if (ip == null || ip.isBlank()) {
            missCounter.increment();
            return Mono.just("UNKNOWN");
        }
        
//        if (isInternalIp(ip)) {
//            log.info("GeoIP bypass for internal IP {}", ip);
//            return Mono.just("INTERNAL");
//        }

        return reactiveRedisTemplate.opsForValue()
                .get("geoip:" + ip)
                .timeout(Duration.ofSeconds(2))
                .doOnNext(country -> {
                    if (country != null) {
                        hitCounter.increment();
                        fallbackCache.put(ip, country);
                    }
                })
                .switchIfEmpty(Mono.defer(() -> {
                    String cached = fallbackCache.getIfPresent(ip);
                    if (cached != null) {
                        hitCounter.increment();
                        return Mono.just(cached);
                    }

                    // REAL MMDB LOOKUP
                    try {
                        InetAddress inetAddress = InetAddress.getByName(ip);
                        CountryResponse response = databaseReader.country(inetAddress);

                        String country = response.getCountry().getIsoCode();
                        if (country == null || country.isBlank()) {
                            missCounter.increment();
                            return Mono.just("UNKNOWN");
                        }
                        
                        hitCounter.increment();
                        fallbackCache.put(ip, country);
                        reactiveRedisTemplate.opsForValue()
                                .set("geoip:" + ip, country, Duration.ofDays(7))
                                .subscribe();

                        return Mono.just(country);

                    } catch (Exception e) {
                        errorCounter.increment();
                        log.error("GeoIP MMDB lookup failed for {}", ip, e);
                        return Mono.just("UNKNOWN");
                    }
                }))
                .onErrorResume(ex -> {
                    errorCounter.increment();
                    log.error("CRITICAL: GeoIP resolution failure for {}", ip, ex);

                    if (geoIPProps.isFailFast()) {
                        return Mono.error(new IllegalStateException("GeoIP unavailable"));
                    }

                    String cached = fallbackCache.getIfPresent(ip);
                    return Mono.just(cached != null ? cached : "UNKNOWN");
                });
    }
    
    private boolean isInternalIp(String ip) {
        return ip.startsWith("127.")
            || ip.startsWith("10.")
            || ip.startsWith("192.168.")
            || ip.startsWith("172.16.")
            || ip.startsWith("172.17.")
            || ip.startsWith("172.18.")
            || ip.startsWith("172.19.")
            || ip.startsWith("172.2")
            || "::1".equals(ip);
    }
    
    public record CountryDecision(String country, boolean blocked, boolean whitelisted, boolean unknown) {}
}
