package com.learn.api_gateway.config;

import java.net.URI;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.cloud.client.circuitbreaker.ReactiveCircuitBreakerFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
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
import com.learn.api_gateway.config.properties.RecaptchaConfigProperties;
import com.learn.api_gateway.util.TraceConstants;

import io.netty.channel.ChannelOption;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import io.netty.resolver.DefaultAddressResolverGroup;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

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
    public WebClient secureWebClient(WebClient.Builder builder) {
    	if (Arrays.asList(env.getActiveProfiles()).contains("prod")) {
    		try {
    			Resource ca = new ClassPathResource("certs/ca.crt");
    			Resource cert = new ClassPathResource("certs/client.crt");
    			Resource key = new ClassPathResource("certs/client.key");

                SslContextBuilder ssl = SslContextBuilder.forClient();
                if (ca.exists()) {
                    ssl.trustManager(ca.getInputStream());
                } else {
                    ssl.trustManager(InsecureTrustManagerFactory.INSTANCE);
                }

                if (cert.exists() && key.exists()) {
                    ssl.keyManager(cert.getInputStream(), key.getInputStream());
                }
                
                SslContext sslContext = ssl.build();

                HttpClient httpClient = HttpClient.create()
                        .secure(s -> s.sslContext(sslContext))
                        .resolver(DefaultAddressResolverGroup.INSTANCE)
                        .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
                        .doOnConnected(conn -> conn
                                .addHandlerLast(new ReadTimeoutHandler(10, TimeUnit.SECONDS))
                                .addHandlerLast(new WriteTimeoutHandler(10, TimeUnit.SECONDS))
                        );

                return builder.clientConnector(new ReactorClientHttpConnector(httpClient))
                        .codecs(c -> c.defaultCodecs().maxInMemorySize(MAX_IN_MEMORY_SIZE))
                        .build();
            } catch (Exception e) {
                log.error("Failed to init secure WebClient: {}", e.getMessage(), e);
                return builder.build();
            }
    	} else {
            log.info("Using non-secure WebClient for dev/local profile");
            return builder.build();
        }
    }

    // === CAPTCHA CLIENT (external, low latency, no CB) ===
//    @Bean
//    public WebClient captchaWebClient(WebClient.Builder builder, RecaptchaConfigProperties props) {
//        ConnectionProvider provider = ConnectionProvider.builder("recaptcha-pool")
//                .maxConnections(props.getPool().getMaxConnections())
//                .maxIdleTime(props.getPool().getMaxIdleTime())
//                .maxLifeTime(props.getPool().getMaxLifeTime())
//                .pendingAcquireTimeout(Duration.ofSeconds(5))
//                .build();
//
//        HttpClient httpClient = HttpClient.create(provider)
//                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, (int) props.getTimeouts().getConnect().toMillis())
//                .responseTimeout(props.getTimeouts().getResponse())
//                .doOnConnected(conn -> conn
//                        .addHandlerLast(new ReadTimeoutHandler((int) props.getTimeouts().getRead().toSeconds(), TimeUnit.SECONDS))
//                        .addHandlerLast(new WriteTimeoutHandler((int) props.getTimeouts().getWrite().toSeconds(), TimeUnit.SECONDS))
//                );
//
//        return builder
//                .baseUrl(props.getBaseUrl())
//                .clientConnector(new ReactorClientHttpConnector(httpClient))
//                .codecs(c -> c.defaultCodecs().maxInMemorySize(MAX_IN_MEMORY_SIZE))
//                .build();
//    }

    // === KEYCLOAK CLIENT ===
    @Bean
    public WebClient keycloakWebClient(WebClient.Builder builder,
            @Value("${spring.profiles.active}") String activeProfile,
            OpaqueTokenProperties opaqueTokenProperties,
            ObjectProvider<WebClient> secureWebClientProvider) {
    	
    	String realmBaseUrl = opaqueTokenProperties.getExpectedIssuer();
    	WebClient.Builder baseBuilder;

        if ("prod".equalsIgnoreCase(activeProfile)) {
            WebClient secureClient = secureWebClientProvider.getIfAvailable();
            if (secureClient != null) {
                baseBuilder = WebClient.builder()
                        .clientConnector(new ReactorClientHttpConnector());
            } else {
                baseBuilder = builder.clone();
            }
        } else {
            baseBuilder = builder.clone();
        }

        var cb = circuitBreakerFactory.create("keycloak");

        return baseBuilder
                .baseUrl(realmBaseUrl)
                .defaultHeaders(h -> {
                    h.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
                    h.setAccept(List.of(MediaType.APPLICATION_JSON));
                })
                .filter(ExchangeFilterFunction.ofResponseProcessor(resp ->
                        cb.run(Mono.just(resp), ex -> {
                            log.warn("Keycloak unavailable: {}", ex.getMessage());
                            return Mono.error(new IllegalStateException("Keycloak unavailable"));
                        })
                ))
                .build();
    }

    // === GEOIP CLIENT ===
    @Bean
    public WebClient geoIpWebClient(WebClient secureWebClient) {
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
