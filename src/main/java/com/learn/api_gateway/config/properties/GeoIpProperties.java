package com.learn.api_gateway.config.properties;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import lombok.Data;

@Configuration
@ConfigurationProperties(prefix="geoip")
@Data
@Validated
public class GeoIpProperties {
	private List<String> blockedCountries = List.of();
    private List<String> highRiskCountries = List.of();

    private String localPath = "/tmp/GeoLite2-Country.mmdb";
    private boolean failFast;

    private Refresh refresh = new Refresh();

    @Data
    public static class Refresh {
        private boolean enabled = true;
        private boolean leaderOnly = false;
        private String remoteUrl; // optional: S3/HTTP for remote sync
        private String expectedSha256; // optional checksum validation
    }
}
