package com.learn.api_gateway.config.properties;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.validation.annotation.Validated;

import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
@ConfigurationProperties(prefix = "gateway.trust")
@Data
@Validated
public class TrustProperties {
	/**
     * CIDR or IP addresses considered trusted.
     * Example: 127.0.0.1, 10.0.0.0/8, 192.168.0.0/16
     */
    private List<String> proxies = new ArrayList<>();

    /**
     * Optional: mark this node as leader for certain cluster tasks.
     */
    private boolean leaderNode = false;

    /**
     * Compiled matchers for trusted IPs/CIDRs.
     */
    private transient volatile List<IpAddressMatcher> matchers = List.of();

    @PostConstruct
    public void init() {
        reloadMatchers();
    }

    /**
     * Check whether an IP is trusted according to the configured CIDRs.
     */
    public boolean isTrusted(String ip) {
        if (ip == null || ip.isBlank()) return false;
        return matchers.stream().anyMatch(m -> m.matches(ip));
    }

    /**
     * Reload proxy matchers after refresh (Cloud Config / Consul).
     */
    @EventListener(org.springframework.cloud.context.scope.refresh.RefreshScopeRefreshedEvent.class)
    public void onRefresh() {
        log.info("Refreshing trusted proxy configuration");
        reloadMatchers();
    }

    private void reloadMatchers() {
        if (proxies.isEmpty()) {
            log.warn("No trusted proxies configured. All incoming remote addresses will be treated as direct client IPs.");
            this.matchers = List.of();
            return;
        }
        this.matchers = proxies.stream()
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(proxy -> {
                    try {
                        return new IpAddressMatcher(proxy);
                    } catch (Exception e) {
                        log.error("Invalid trusted proxy entry [{}], skipping: {}", proxy, e.getMessage());
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .toList();

        log.info("Configured trusted proxies: {}", proxies);
    }
}
