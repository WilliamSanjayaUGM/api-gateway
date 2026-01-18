package com.learn.api_gateway.config;

import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import reactor.core.publisher.Hooks;

@Configuration
public class ReactorMdcConfig {
	
	private static final String MDC_HOOK_KEY = "mdcHook";

    @PostConstruct
    public void init() {
    }

    @PreDestroy
    public void cleanup() {
        Hooks.resetOnEachOperator(MDC_HOOK_KEY);
    }
}
