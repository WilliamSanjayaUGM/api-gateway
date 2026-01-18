package com.learn.api_gateway.config.properties;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import lombok.Data;

@Configuration
@ConfigurationProperties(prefix = "bucket4j")
@Data
@Validated
public class Bucket4jProperties {
	
	private boolean enabled = true;
    private List<BucketFilterConfig> filters = new ArrayList<>();
    
    private Boolean failOpen = false;
    private boolean includePathInKey = false;
    private long maxResetSeconds = 86400;

    @Data
    public static class BucketFilterConfig {
        private String cacheName;
        private String url;
        private String service; 
        private String keyResolver;
        private List<RateLimit> rateLimits;
        private int httpStatus = 429;
        private String filterName;

        @Data
        public static class RateLimit {
            private List<BandwidthDef> bandwidths;
        }

        @Data
        public static class BandwidthDef {
            private long capacity;
            private long time;
            private String unit; // e.g. seconds
            private String refillSpeed; // interval or greedy
        }
    }
}
