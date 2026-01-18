package com.learn.api_gateway.config;

import java.time.Clock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ClockConfig {
	@Bean
    public Clock clock() {
        // Uses the system default timezone and current time
        return Clock.systemDefaultZone();
    }
}
