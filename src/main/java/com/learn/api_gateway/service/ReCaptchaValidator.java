package com.learn.api_gateway.service;

import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

import org.slf4j.MDC;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientException;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.learn.api_gateway.config.properties.RecaptchaConfigProperties;
import com.learn.api_gateway.util.IpRateLimiter;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.reactor.circuitbreaker.operator.CircuitBreakerOperator;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.util.retry.Retry;
import reactor.util.retry.RetryBackoffSpec;

@Slf4j
@Component
public class ReCaptchaValidator {
	private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
    private final RecaptchaConfigProperties props;
    private WebClient captchaWebClient;
    private final CircuitBreaker circuitBreaker;
    private final MeterRegistry meterRegistry;
    private final IpRateLimiter ipRateLimiter;
    private final Environment env;
    private final HmacService hmacService;
    
    private final WebClient.Builder webClientBuilder;
    private final HttpClient httpClient;

    private final Counter captchaSuccessCounter;
    private final Counter captchaFailureCounter;
    private final Counter captchaErrorCounter;
    private final DistributionSummary captchaScoreDistribution;
    private final com.github.benmanes.caffeine.cache.Cache<String, Boolean> localResultCache;

    private final String replayPrefix;

    @Getter
    public enum FailMode { CLOSED, OPEN }

    public ReCaptchaValidator(
            ReactiveRedisTemplate<String, String> reactiveRedisTemplate,
            RecaptchaConfigProperties props,
            WebClient.Builder webClientBuilder,
            CircuitBreakerRegistry circuitBreakerRegistry,
            MeterRegistry meterRegistry,
            IpRateLimiter ipRateLimiter,
            Environment env,
            HmacService hmacService) {
        this.reactiveRedisTemplate = reactiveRedisTemplate;
        this.props = props;
        this.ipRateLimiter = ipRateLimiter;
        this.meterRegistry = meterRegistry;
        this.env = env;
        this.hmacService = hmacService;

        this.captchaSuccessCounter = Counter.builder("captcha.success.total").register(meterRegistry);
        this.captchaFailureCounter = Counter.builder("captcha.failure.total").register(meterRegistry);
        this.captchaErrorCounter = Counter.builder("captcha.error.total").register(meterRegistry);
        this.captchaScoreDistribution = DistributionSummary.builder("captcha.score").register(meterRegistry);
        
        this.webClientBuilder=webClientBuilder;
        
        Duration httpTimeout = Optional.ofNullable(props.getTimeouts())
                .map(RecaptchaConfigProperties.Timeouts::getResponse)
                .orElse(Duration.ofSeconds(5));
        
        
        
        HttpClient httpClient = HttpClient.create().responseTimeout(httpTimeout);
        this.httpClient = httpClient;
        this.circuitBreaker = circuitBreakerRegistry.circuitBreaker("recaptcha-api");
        
        Duration effectiveTtl = props.getLocalCacheTtl().compareTo(props.getTokenTtl()) > 0
                ? props.getTokenTtl()
                : props.getLocalCacheTtl();

        this.localResultCache = Caffeine.newBuilder()
                .expireAfterWrite(effectiveTtl)
                .maximumSize(50_000)
                .build();

        this.replayPrefix = Optional.ofNullable(props.getReplayPrefix())
                .filter(StringUtils::hasText)
                .orElse("RECAPTCHA_USED:");
    }
    
    @EventListener(ApplicationReadyEvent.class)
    public void initWebClientWhenReady() {
        try {
            log.info("Initializing Props baseUrl = {}", props.getBaseUrl());
            if (props.getBaseUrl() == null) {
                throw new IllegalStateException("Recaptcha base URL is null!");
            }
            this.captchaWebClient = webClientBuilder
                    .baseUrl(props.getBaseUrl())
                    .clientConnector(new ReactorClientHttpConnector(httpClient))
                    .build();
            log.info("ReCaptcha WebClient initialized successfully");
        } catch (Exception e) {
            log.error("Failed to initialize ReCaptcha WebClient: {}", e.getMessage(), e);
        }
    }

    public Mono<Boolean> validate(String token, String clientIp, String expectedAction, String endpointKey) {
        if (!StringUtils.hasText(token)) return Mono.just(false);

        String envName = Arrays.stream(env.getActiveProfiles()).findFirst().orElse("default");
        String maskedIp = maskIpNormalized(clientIp);
        String traceId = Optional.ofNullable(MDC.get("X-Trace-Id")).orElse(UUID.randomUUID().toString());
        
        return hmacService.sign(token, "primary")
                .flatMap(tokenHash -> {
                    String redisKey = replayPrefix + envName + ":" + endpointKey + ":" + tokenHash;
                    Boolean cached = localResultCache.getIfPresent(redisKey);
                    if (cached != null) {
                        log.debug("[traceId={}] Cache hit endpoint={} ip={} result={}", traceId, endpointKey, maskedIp, cached);
                        return Mono.just(cached);
                    }
                    
                    log.info("[traceId={}] From RecaptchaValidator.validate - before isAllowed",
                    	    traceId, token);
                    
                    return ipRateLimiter.isAllowed(clientIp, props.getRateLimitWindow(), props.getRateLimitMaxFailures())
                            .flatMap(allowed -> allowed
                                    ? attemptVerify(token, clientIp, expectedAction, endpointKey, redisKey, tokenHash, maskedIp, traceId)
                                    : handleRateLimitExceeded(redisKey, maskedIp, endpointKey, traceId))
                            .timeout(props.getTimeouts().getResponse())
                            .onErrorResume(ex -> handleGlobalError(redisKey, maskedIp, endpointKey, token, ex, traceId));
                });
    }

    private Mono<Boolean> attemptVerify(String token, String clientIp, String expectedAction,
                                        String endpointKey, String redisKey, String tokenHash,
                                        String maskedIp, String traceId) {

        Duration shortLockTtl = Duration.ofSeconds(Math.min(props.getTokenTtl().getSeconds(), 60));

        return reactiveRedisTemplate.opsForValue().setIfAbsent(redisKey, maskedIp, shortLockTtl)
                .flatMap(acquired -> {
                    if (!Boolean.TRUE.equals(acquired)) {
                        log.warn("[traceId={}] Replay detected tokenHash={} ip={} endpoint={}",
                                traceId, tokenHash, maskedIp, endpointKey);
                        return failCaptcha(redisKey);
                    }

                    return captchaWebClient.post()
                            .uri("/recaptcha/api/siteverify")
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .body(BodyInserters.fromFormData("secret", props.getSecretKey())
                                    .with("response", token)
                                    .with("remoteip", clientIp))
                            .retrieve()
                            .bodyToMono(CaptchaResponse.class)
                            .timeout(props.getTimeouts().getResponse())
                            .retryWhen(retrySpec())
                            .transformDeferred(CircuitBreakerOperator.of(circuitBreaker))
                            .flatMap(resp -> validateResponse(resp, redisKey, maskedIp, expectedAction, endpointKey, traceId))
                            .onErrorResume(ex -> handleError(redisKey, maskedIp, endpointKey, token, ex, traceId));
                });
    }

    private RetryBackoffSpec retrySpec() {
        return Retry.backoff(2, Duration.ofMillis(200))
                .maxBackoff(Duration.ofSeconds(2))
                .filter(ex -> ex instanceof WebClientException)
                .doBeforeRetry(rs -> log.warn("Retrying captcha verification after {} due to {}",
                        rs.totalRetriesInARow(), rs.failure().toString()));
    }

    private Mono<Boolean> validateResponse(CaptchaResponse resp, String redisKey,
                                           String maskedIp, String expectedAction,
                                           String endpointKey, String traceId) {
        if (resp == null) return failCaptcha(redisKey);

        captchaScoreDistribution.record(resp.getScore());
        boolean valid = resp.isSuccess() && resp.getScore() >= props.getMinScore();

        if (StringUtils.hasText(expectedAction) && !expectedAction.equals(resp.getAction())) {
            log.warn("[traceId={}] Captcha action mismatch expected={} actual={} ip={} endpoint={}",
                    traceId, expectedAction, resp.getAction(), maskedIp, endpointKey);
            valid = false;
        }

        if (!props.getExpectedHostnames().isEmpty() && !matchesExpectedHostname(resp.getHostname())) {
            log.warn("[traceId={}] Captcha hostname mismatch expected={} actual={} ip={} endpoint={}",
                    traceId, props.getExpectedHostnames(), resp.getHostname(), maskedIp, endpointKey);
            valid = false;
        }

        if (!valid) return failCaptcha(redisKey);

        captchaSuccessCounter.increment();
        localResultCache.put(redisKey, true);
        return reactiveRedisTemplate.opsForValue().set(redisKey, "PASS:" + maskedIp, props.getTokenTtl()).thenReturn(true);
    }

    private Mono<Boolean> failCaptcha(String redisKey) {
        captchaFailureCounter.increment();
        localResultCache.put(redisKey, false);
        return reactiveRedisTemplate.opsForValue().set(redisKey, "FAIL", props.getTokenTtl()).thenReturn(false);
    }

    private Mono<Boolean> handleRateLimitExceeded(String redisKey, String maskedIp, String endpointKey, String traceId) {
        log.warn("[traceId={}] Captcha rate limit exceeded endpoint={} ip={} comes from ReCaptchaValidator------------", traceId, endpointKey, maskedIp);
        captchaFailureCounter.increment();
        localResultCache.put(redisKey, false);
        return reactiveRedisTemplate.expire(redisKey, Duration.ofMinutes(1)).thenReturn(false);
    }

    private Mono<Boolean> handleGlobalError(String redisKey, String maskedIp, String endpointKey,
                                            String token, Throwable e, String traceId) {
        log.error("[traceId={}] Captcha validation failed endpoint={} ip={} error={}", traceId, endpointKey, maskedIp, e.toString());
        captchaErrorCounter.increment();
        return handleFailMode(redisKey, maskedIp, endpointKey, token, traceId);
    }

    private Mono<Boolean> handleError(String redisKey, String maskedIp, String endpointKey,
                                      String token, Throwable e, String traceId) {
        log.error("[traceId={}] Captcha API error endpoint={} ip={} err={}", traceId, endpointKey, maskedIp, e.toString());
        captchaErrorCounter.increment();
        return handleFailMode(redisKey, maskedIp, endpointKey, token, traceId);
    }

    private Mono<Boolean> handleFailMode(String redisKey, String maskedIp,
                                         String endpointKey, String token, String traceId) {
        FailMode mode = Optional.ofNullable(props.getFailMode(endpointKey)).orElse(FailMode.CLOSED);
        boolean isProd = Arrays.stream(env.getActiveProfiles())
                .anyMatch(p -> p.equalsIgnoreCase("prod") || p.equalsIgnoreCase("production"));

        if (isProd && mode == FailMode.OPEN) {
            log.warn("[traceId={}] Fail-open requested but running in prod, overriding to CLOSED", traceId);
            mode = FailMode.CLOSED;
        }

        if (mode == FailMode.OPEN) {
            log.warn("[traceId={}] Fail-open allowing request endpoint={} ip={}", traceId, endpointKey, maskedIp);
            localResultCache.put(redisKey, true);
            return reactiveRedisTemplate.opsForValue().set(redisKey, "PASS", Duration.ofMinutes(1)).thenReturn(true);
        }

        log.warn("[traceId={}] Fail-closed rejecting request endpoint={} ip={}", traceId, endpointKey, maskedIp);
        localResultCache.put(redisKey, false);
        return reactiveRedisTemplate.opsForValue().set(redisKey, "FAIL", Duration.ofMinutes(1)).thenReturn(false);
    }

    private boolean matchesExpectedHostname(String hostname) {
        if (hostname == null) return false;
        return props.getExpectedHostnames().stream().anyMatch(expected -> {
            if (expected.startsWith("*.")) return hostname.endsWith(expected.substring(1));
            return expected.equalsIgnoreCase(hostname);
        });
    }

    private String maskIpNormalized(String ip) {
        if (ip == null) return "unknown";
        try {
            String cleaned = ip.trim();
            if (cleaned.startsWith("::ffff:")) cleaned = cleaned.substring(7);
            String[] parts = cleaned.split("\\.");
            if (parts.length == 4) {
                return parts[0] + "." + parts[1] + "." + parts[2] + ".xxx";
            }
            return cleaned.split(":")[0] + "::xxxx";
        } catch (Exception e) {
            return "unknown";
        }
    }

    public static class CaptchaResponse {
        @JsonProperty("success") private boolean success;
        @JsonProperty("score") private double score;
        @JsonProperty("action") private String action;
        @JsonProperty("hostname") private String hostname;

        public boolean isSuccess() { return success; }
        public double getScore() { return score; }
        public String getAction() { return action; }
        public String getHostname() { return hostname; }
    }
}
