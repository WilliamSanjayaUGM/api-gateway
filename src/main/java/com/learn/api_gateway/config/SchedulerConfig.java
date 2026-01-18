package com.learn.api_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

@Configuration
public class SchedulerConfig {
	
	@Bean(destroyMethod = "dispose")
    public Scheduler leaderElectionScheduler() {
        return Schedulers.newSingle("leader-election");
    }
}
