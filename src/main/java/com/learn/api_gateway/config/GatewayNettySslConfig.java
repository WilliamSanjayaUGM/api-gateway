package com.learn.api_gateway.config;

import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.cloud.gateway.config.HttpClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.Resource;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import reactor.netty.http.client.HttpClient;

@Configuration
public class GatewayNettySslConfig {

    @Bean
    public SslContext gatewayClientSslContext(
            @Value("${spring.cloud.gateway.server.webflux.httpclient.ssl.key-store}") Resource keyStore,
            @Value("${spring.cloud.gateway.server.webflux.httpclient.ssl.key-store-password}") String keyStorePassword,
            @Value("${spring.cloud.gateway.server.webflux.httpclient.ssl.trust-store}") Resource trustStore,
            @Value("${spring.cloud.gateway.server.webflux.httpclient.ssl.trust-store-password}") String trustStorePassword
    ) throws Exception {

        // ---- Load client key (api-gateway cert) ----
        KeyStore clientKeyStore = KeyStore.getInstance("PKCS12");
        clientKeyStore.load(
                keyStore.getInputStream(),
                keyStorePassword.toCharArray()
        );

        KeyManagerFactory kmf =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(clientKeyStore, keyStorePassword.toCharArray());

        // ---- Load trusted CAs (GlobalBank Root + Issuing) ----
        KeyStore trustKeyStore = KeyStore.getInstance("PKCS12");
        trustKeyStore.load(
                trustStore.getInputStream(),
                trustStorePassword.toCharArray()
        );

        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustKeyStore);

        // ---- Build Netty SSLContext ----
        return SslContextBuilder.forClient()
                .keyManager(kmf)          // mTLS client cert
                .trustManager(tmf)        // PKIX trust path
                .protocols("TLSv1.3", "TLSv1.2")
                .build();
    }

    @Bean
    public HttpClient gatewayHttpClient(SslContext gatewayClientSslContext) {
        return HttpClient.create()
                .secure(ssl -> ssl.sslContext(gatewayClientSslContext));
    }

    @Bean
    @ConditionalOnMissingBean
    public HttpClientCustomizer gatewayHttpClientCustomizer(
            HttpClient gatewayHttpClient) {
        return httpClient -> gatewayHttpClient;
    }
    
//    @Bean
//    @Primary
//    public WebClient webClientBuilderTls(HttpClient gatewayHttpClient) {
//        return WebClient.builder()
//                .clientConnector(new ReactorClientHttpConnector(gatewayHttpClient)).build();
//    }
}
