package com.learn.api_gateway.filter;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.learn.api_gateway.config.properties.Bucket4jProperties;
import com.learn.api_gateway.config.properties.Bucket4jProperties.BucketFilterConfig.BandwidthDef;
import com.learn.api_gateway.resolver.AuthenticatedUserKeyResolver;
import com.learn.api_gateway.resolver.UserIpKeyResolver;
import com.learn.api_gateway.util.ErrorResponseWriter;
import com.learn.api_gateway.util.ReactorMdc;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.ConfigurationBuilder;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.distributed.AsyncBucketProxy;
import io.github.bucket4j.local.LocalBucketBuilder;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.reactor.circuitbreaker.operator.CircuitBreakerOperator;
import io.github.resilience4j.reactor.retry.RetryOperator;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryRegistry;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class Bucket4jRateLimitGatewayFilterFactory extends AbstractGatewayFilterFactory<Bucket4jRateLimitGatewayFilterFactory.Config>{
	private static final long MAX_RESET_SECONDS = 86_400; // 1 day fallback

    private final LettuceBasedProxyManager<String> proxyManager;
    private final MeterRegistry meterRegistry;
    private final Cache<String, AsyncBucketProxy> bucketCache;
    private final boolean globalFailOpenDefault;
    private final CircuitBreaker circuitBreaker;
    private final Retry retry;

    private final Map<String, KeyResolver> resolverRegistry;
    private final ErrorResponseWriter errorResponseWriter;

    @Value("${bucket4j.timeout-ms:1000}")
    private long redisTimeoutMs;

    // Local fallback cache for fail-open scenarios
    private final Cache<String, Bucket> localFallbackBuckets = Caffeine.newBuilder()
            .expireAfterAccess(Duration.ofMinutes(30))
            .maximumSize(10_000)
            .recordStats()
            .build();

    public Bucket4jRateLimitGatewayFilterFactory(
    		LettuceBasedProxyManager<String> proxyManager,
            MeterRegistry meterRegistry,
            CircuitBreakerRegistry cbRegistry,
            RetryRegistry retryRegistry,
            UserIpKeyResolver userIpKeyResolver,
            AuthenticatedUserKeyResolver authenticatedUserKeyResolver,
            ErrorResponseWriter errorResponseWriter,
            @Value("${bucket4j.cache.max-size:10000}") int maxCacheSize,
            @Value("${bucket4j.fail-open-default:true}") boolean failOpenDefault) {

        super(Config.class);
        this.proxyManager = proxyManager;
        this.meterRegistry = meterRegistry;
        this.globalFailOpenDefault = failOpenDefault;
        this.errorResponseWriter=errorResponseWriter;

        this.bucketCache = Caffeine.<String, AsyncBucketProxy>newBuilder()
                .expireAfterAccess(Duration.ofMinutes(30))
                .maximumSize(maxCacheSize)
                .recordStats()
                .removalListener((key, value, cause) -> {
                    if (cause != null && cause.wasEvicted()) {
                        log.debug("Evicted bucket for key={} due to {}", key, cause);
                        meterRegistry.counter("gateway.rate_limit.bucket.evictions",
                                "cause", cause.name()).increment();
                    }
                })
                .build();

        Metrics.gauge("gateway.rate_limit.bucket.cache.size", bucketCache, Cache::estimatedSize);

        this.circuitBreaker = cbRegistry.circuitBreaker("bucket4j-redis");
        this.retry = retryRegistry.retry("bucket4j-redis");

        // Register available resolvers
        this.resolverRegistry = Map.of(
                "userIpKeyResolver", userIpKeyResolver,
                "authenticatedUserKeyResolver", authenticatedUserKeyResolver
        );
    }

    private Duration redisTimeout() {
        return Duration.ofMillis(redisTimeoutMs);
    }

    @Override
    public GatewayFilter apply(Config config) {
        BucketConfiguration bucketConfiguration = buildBucketConfiguration(config);
        boolean failOpen = (config.failOpen != null) ? config.failOpen : globalFailOpenDefault;

        // Build policy header string
        String policy = config.getRateLimits().stream()
                .flatMap(rl -> rl.getBandwidths().stream())
                .map(bw -> bw.getCapacity() + "r/" + bw.getTime() + "s")
                .collect(Collectors.joining(";"));

        return (exchange, chain) ->
                resolveKey(exchange, config)
                        .flatMap(key -> {
                            if (key == null) return chain.filter(exchange);

                            Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
                            String routeId = (route != null && route.getId() != null) ? route.getId() : null;

                            String redisKey = String.format("bucket:%s:%s%s",
                                    Optional.ofNullable(config.getCacheName()).orElse("default"),
                                    (routeId != null ? routeId + ":" : ""),
                                    key);

                            if (config.isIncludePathInKey()) {
                                redisKey += ":" + exchange.getRequest().getPath().value();
                            }

                            return tryConsume(redisKey, config, bucketConfiguration, failOpen)
                                    .flatMap(probe -> {
                                        HttpHeaders headers = exchange.getResponse().getHeaders();

                                        long limit = config.getRateLimits().stream()
                                        	    .flatMap(rl -> rl.getBandwidths().stream())
                                        	    .mapToLong(BandwidthDef::getCapacity)
                                        	    .min()
                                        	    .orElse(0);

                                        headers.set("X-RateLimit-Limit", String.valueOf(limit));
                                        headers.set("X-RateLimit-Remaining",
                                                String.valueOf(probe.isConsumed() ? probe.getRemainingTokens() : 0));

                                        long resetSeconds = Math.min(
                                                TimeUnit.NANOSECONDS.toSeconds(probe.getNanosToWaitForRefill()),
                                                config.getMaxResetSeconds());
                                        headers.set("X-RateLimit-Reset", String.valueOf(resetSeconds));
                                        headers.set("X-RateLimit-Policy", policy);

                                        if (!probe.isConsumed()) {
                                            meterRegistry.counter("gateway.rate_limit.rejected",
                                                    "cacheName", config.getCacheName()).increment();
                                            log.debug("Rate limit exceeded for key={}, retry after {}s", key, resetSeconds);

                                            headers.set("Retry-After", String.valueOf(resetSeconds));
                                            exchange.getResponse().setStatusCode(HttpStatus.valueOf(config.getHttpStatus()));
                                            return errorResponseWriter.write(exchange,
                                                    HttpStatus.valueOf(config.getHttpStatus()),
                                                    "Rate limit exceeded. Retry after " + resetSeconds + " seconds.");
                                        }
                                        
                                        log.info("-----------Bucket4JRate Limit filter is passed-----------------");
                                        return chain.filter(exchange);
                                    });
                        })
                        .transformDeferred(ReactorMdc.mdcOperatorVoid());
    }

    private Mono<String> resolveKey(ServerWebExchange exchange, Config config) {
        if (config.getKeyResolver() == null) {
            return resolverRegistry.get("userIpKeyResolver").resolve(exchange);
        }

        KeyResolver resolver = resolverRegistry.get(config.getKeyResolver());
        if (resolver != null) {
            return resolver.resolve(exchange);
        }

        log.warn("Unknown KeyResolver '{}', falling back to userIpKeyResolver", config.getKeyResolver());
        return resolverRegistry.get("userIpKeyResolver").resolve(exchange);
    }

    private Mono<ConsumptionProbe> tryConsume(String redisKey, Config config,
	            BucketConfiguration bucketConfig, boolean failOpen) {
		AsyncBucketProxy asyncBucket = bucketCache.get(redisKey,k -> proxyManager.asAsync().builder().build(k, bucketConfig));
		
		return Mono.defer(() -> Mono.fromCompletionStage(asyncBucket.tryConsumeAndReturnRemaining(1)))
				.transformDeferred(CircuitBreakerOperator.of(circuitBreaker))
				.transformDeferred(RetryOperator.of(retry))
				.timeout(redisTimeout())
				.onErrorResume(ex -> {
						meterRegistry.counter("gateway.rate_limit.redis.errors","cacheName", config.getCacheName(),
								"exception", ex.getClass().getSimpleName()).increment();
			
						log.error("Redis unavailable for key={}, failOpen={} : {}", redisKey, failOpen, ex.toString());
			
			if (failOpen) {
				meterRegistry.counter("gateway.rate_limit.failover","cacheName", config.getCacheName(),
						"route", Optional.ofNullable(config.getCacheName()).orElse("unknown"))
				.increment();
				
				// Optional: escalate log level if frequent
				log.warn("Failing open for key={} using local fallback bucket (Redis issue).", redisKey);
				
				Bucket localBucket = localFallbackBuckets.get(redisKey, k -> createLocalFallbackBucket(config));
				ConsumptionProbe probe = localBucket.tryConsumeAndReturnRemaining(1);
				
				// track fallback bucket stats too
				if (!probe.isConsumed()) {
					meterRegistry.counter("gateway.rate_limit.failover.rejected",
							"cacheName", config.getCacheName()).increment();
				}
				
				return Mono.just(probe);
			} else {
				return Mono.just(ConsumptionProbe.rejected(
				0, 0, TimeUnit.SECONDS.toNanos(config.getMaxResetSeconds())));
			}
		});
	}

    private Bucket createLocalFallbackBucket(Config config) {
        List<Bandwidth> limits = new ArrayList<>();
        for (Bucket4jProperties.BucketFilterConfig.RateLimit rl : config.getRateLimits()) {
            for (Bucket4jProperties.BucketFilterConfig.BandwidthDef bw : rl.getBandwidths()) {
                Duration duration = Duration.ofSeconds(bw.getTime());
                Bandwidth limit = "greedy".equalsIgnoreCase(bw.getRefillSpeed())
                        ? Bandwidth.builder().capacity(bw.getCapacity()).refillGreedy(bw.getCapacity(), duration).build()
                        : Bandwidth.builder().capacity(bw.getCapacity()).refillIntervally(bw.getCapacity(), duration).build();
                limits.add(limit);
            }
        }
        LocalBucketBuilder builder = Bucket.builder();
        limits.forEach(builder::addLimit);
        return builder.build();
    }

    private BucketConfiguration buildBucketConfiguration(Config config) {
        List<Bandwidth> limits = new ArrayList<>();
        for (Bucket4jProperties.BucketFilterConfig.RateLimit rl : config.getRateLimits()) {
            for (Bucket4jProperties.BucketFilterConfig.BandwidthDef bw : rl.getBandwidths()) {
                Duration duration = Duration.ofSeconds(bw.getTime());
                Bandwidth limit = "greedy".equalsIgnoreCase(bw.getRefillSpeed())
                        ? Bandwidth.builder().capacity(bw.getCapacity()).refillGreedy(bw.getCapacity(), duration).build()
                        : Bandwidth.builder().capacity(bw.getCapacity()).refillIntervally(bw.getCapacity(), duration).build();
                limits.add(limit);
            }
        }
        ConfigurationBuilder bucketConfig = BucketConfiguration.builder();
        limits.forEach(bucketConfig::addLimit);
        return bucketConfig.build();
    }

    @Data
    public static class Config {
        private String cacheName;
        private String keyResolver;
        private List<Bucket4jProperties.BucketFilterConfig.RateLimit> rateLimits;
        private int httpStatus = 429;
        private Boolean failOpen;
        private boolean includePathInKey = false;
        private long maxResetSeconds = MAX_RESET_SECONDS;
    }
}
