package com.learn.api_gateway.config;

import java.security.KeyStore;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.JdkClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class KeycloakClientConfig {
	
	@Bean
    public SSLContext jdkSslContext(
    		@Value("${server.ssl.trust-store}") Resource trustStore,
            @Value("${server.ssl.trust-store-password}") String password
    ) throws Exception {

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(trustStore.getInputStream(), password.toCharArray());

        TrustManagerFactory tmf =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);

        return ctx;
    }
	
    @Bean
    @Qualifier("keycloakWebClient")
    public WebClient keycloakWebClient(SSLContext jdkSslContext,
                                       @Value("${keycloak.server-url}") String baseUrl) {

        return WebClient.builder()
                .baseUrl(baseUrl)
                .clientConnector(
                        new JdkClientHttpConnector(
                                java.net.http.HttpClient.newBuilder()
                                        .sslContext(jdkSslContext)
                                        .build()
                        )
                )
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .build();
    }
}
