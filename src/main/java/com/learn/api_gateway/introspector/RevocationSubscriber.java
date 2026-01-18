package com.learn.api_gateway.introspector;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;

import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.ReactiveRedisMessageListenerContainer;
import org.springframework.stereotype.Component;

import com.learn.api_gateway.service.TokenRevocationService;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.Disposable;
import reactor.util.retry.Retry;
import reactor.core.publisher.Mono;

/**
 * Used inside introspect CachingRevocationAwareIntrospector
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RevocationSubscriber {
	private static final String REVOCATION_CHANNEL = "gateway:revocations";

    private final ReactiveRedisMessageListenerContainer redisListener;
    private final TokenRevocationService tokenRevocationService;
    private final LocalRevocationEvictor localEvictor;

    private Disposable subscription;

    @PostConstruct
    public void subscribe() {
        var topic = ChannelTopic.of(REVOCATION_CHANNEL);

        subscription = redisListener.receive(topic)
                .map(msg -> decodeMessage(msg.getMessage()))
                .filter(Objects::nonNull)
                .flatMap(tokenHash ->
                        Mono.defer(() -> tokenRevocationService.revokeToken(tokenHash, Duration.ofMinutes(10)))
                                .then(localEvictor.handleRevocationPayload(tokenHash))
                                .doOnSuccess(v -> log.info("Token revoked & local cache evicted for {}", tokenHash))
                                .onErrorResume(ex -> {
                                    log.error("Failed to process revocation for {}", tokenHash, ex);
                                    return Mono.empty();
                                })
                )
                .doOnError(ex -> log.error("Redis subscription error", ex))
                .retryWhen(
                        Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(2))
                                .maxBackoff(Duration.ofMinutes(1))
                                .jitter(0.25)
                                .doBeforeRetry(sig -> log.warn(
                                        "Retrying Redis revocation subscription after error: {}",
                                        sig.failure().toString()))
                )
                .subscribe(
                        null,
                        ex -> log.error("Fatal Redis subscription failure", ex),
                        () -> log.warn("Redis revocation subscription completed unexpectedly")
                );
    }

    @PreDestroy
    public void stop() {
        if (subscription != null && !subscription.isDisposed()) {
            log.info("Disposing Redis revocation subscription...");
            subscription.dispose();
        }
    }

    private String decodeMessage(Object raw) {
        if (raw == null) return null;
        if (raw instanceof String s) return s;
        if (raw instanceof byte[] bytes) return new String(bytes, StandardCharsets.UTF_8);
        if (raw instanceof ByteBuffer buffer) {
            byte[] arr = new byte[buffer.remaining()];
            buffer.get(arr);
            return new String(arr, StandardCharsets.UTF_8);
        }
        return String.valueOf(raw);
    }
}
