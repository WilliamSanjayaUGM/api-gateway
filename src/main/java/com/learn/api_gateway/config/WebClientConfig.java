package com.learn.api_gateway.config;

import java.net.URI;
import java.util.List;

import javax.net.ssl.SSLException;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.cloud.client.circuitbreaker.ReactiveCircuitBreakerFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFilterFunctions;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import com.learn.api_gateway.config.properties.GeoIpProperties;
import com.learn.api_gateway.config.properties.OpaqueTokenProperties;
import com.learn.api_gateway.util.TraceConstants;

import io.netty.channel.ChannelOption;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

@Configuration
@Slf4j
@RequiredArgsConstructor
public class WebClientConfig {
	private final OpaqueTokenProperties opaqueTokenProperties;
    private final GeoIpProperties geoIpProperties;
    private final ReactiveCircuitBreakerFactory<?, ?> circuitBreakerFactory;

    @Value("${spring.application.name:api-gateway}")
    private String appName;

    private static final int MAX_IN_MEMORY_SIZE = 2 * 1024 * 1024;
    private final Environment env;

    // === GLOBAL BASE BUILDER ===
    @Bean
    public WebClient.Builder webClientBuilder() {
    	return WebClient.builder()
                .filter(addTraceContextHeadersFilter())
                .filter(ExchangeFilterFunctions.statusError(
                        HttpStatusCode::isError,
                        resp -> new WebClientResponseException(
                                "Downstream error: " + resp.statusCode(),
                                resp.statusCode().value(),
                                "",
                                resp.headers().asHttpHeaders(),
                                null,
                                null
                        )
                ))
                .filter(logRequest())
                .filter(logResponse());
    }
    
    private ExchangeFilterFunction addTraceContextHeadersFilter() {
        return (request, next) -> {
            return Mono.deferContextual(ctxView -> {
                ClientRequest.Builder builder = ClientRequest.from(request);

                // Add context keys if they exist
                ctxView.getOrEmpty(TraceConstants.TRACE_ID_CONTEXT_KEY)
                        .ifPresent(v -> builder.header(TraceConstants.TRACE_ID_HEADER, v.toString()));
                ctxView.getOrEmpty(TraceConstants.CLIENT_IP_CONTEXT_KEY)
                        .ifPresent(v -> builder.header("X-Client-Ip", v.toString()));
                ctxView.getOrEmpty(TraceConstants.USER_ID_CONTEXT_KEY)
                        .ifPresent(v -> builder.header("X-User-Id", v.toString()));

                return next.exchange(builder.build());
            }).contextWrite(context -> context); // ensure context propagation continues
        };
    }

    // === SECURE WEBCLIENT (mTLS) ===
    @Bean
    @Primary
    public WebClient secureWebClient(WebClient.Builder builder, SslBundles sslBundles) {
    	SslBundle bundle = sslBundles.getBundle("internal-mtls");

        SslContext nettySslContext;
        try {
            nettySslContext =
                    SslContextBuilder.forClient()
                            .keyManager(bundle.getManagers().getKeyManagerFactory())
                            .trustManager(bundle.getManagers().getTrustManagerFactory())
                            .protocols("TLSv1.3", "TLSv1.2")
                            .build();
        } catch (SSLException e) {
            throw new IllegalStateException("Failed to build Netty SSL context for mTLS", e);
        }

        HttpClient httpClient =
                HttpClient.create()
                        .secure(ssl -> ssl.sslContext(nettySslContext))
                        .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
                        .doOnConnected(conn -> conn
                                .addHandlerLast(new ReadTimeoutHandler(10))
                                .addHandlerLast(new WriteTimeoutHandler(10))
                        );

        return builder
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .codecs(c -> c.defaultCodecs().maxInMemorySize(MAX_IN_MEMORY_SIZE))
                .build();
    }

    // === GEOIP CLIENT ===
    @Bean
    public WebClient geoIpWebClient(@Qualifier("secureWebClient") WebClient secureWebClient) {
        String remoteUrl = geoIpProperties.getRefresh().getRemoteUrl();
        var cb = circuitBreakerFactory.create("geoip-service");

        return secureWebClient.mutate()
                .baseUrl(remoteUrl)
                .filter(ExchangeFilterFunction.ofResponseProcessor(resp ->
                        cb.run(Mono.just(resp), ex -> {
                            log.warn("GeoIP service unavailable: {}", ex.getMessage());
                            return Mono.error(new IllegalStateException("GeoIP unavailable"));
                        })
                ))
                .build();
    }

    // === LOGGING ===    
    private ExchangeFilterFunction logRequest() {
        return (request, next) -> {
            log.debug("➡️ WebClient Request: {} {}", request.method(), request.url());
            return next.exchange(request);
        };
    }

    private ExchangeFilterFunction logResponse() {
        return ExchangeFilterFunction.ofResponseProcessor(response -> {
            log.debug("⬅️ WebClient Response: {}", response.statusCode());
            return Mono.just(response);
        });
    }

    private String deriveBaseUrl(String uri) {
        try {
            URI parsed = URI.create(uri);
            return parsed.resolve("/").toString().replaceAll("/$", "");
        } catch (Exception e) {
            log.warn("Invalid URI: {}, fallback to original", uri);
            return uri;
        }
    }
    
    // === GRACEFUL REDIS SHUTDOWN ===
    @Bean
    public SmartLifecycle gracefulShutdown(LettuceConnectionFactory lettuce) {
        return new SmartLifecycle() {
            private volatile boolean running;

            @Override
            public void start() {
                running = true;
            }

            @Override
            public void stop() {
                try {
                    lettuce.destroy();
                    log.info("Redis connection closed gracefully.");
                } catch (Exception e) {
                    log.warn("Error during Redis shutdown: {}", e.getMessage());
                } finally {
                    running = false;
                }
            }

            @Override
            public boolean isRunning() {
                return running;
            }
        };
    }

    // Optional logging when app is ready
    @EventListener(ApplicationReadyEvent.class)
    public void onReady() {
        log.info("WebClientConfig initialized successfully for {}", appName);
    }
}
