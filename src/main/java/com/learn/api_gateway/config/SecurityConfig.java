package com.learn.api_gateway.config;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter.Mode;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.WebSessionIdResolver;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.learn.api_gateway.config.properties.OpaqueTokenProperties;
import com.learn.api_gateway.config.properties.SecurityCacheProperties;
import com.learn.api_gateway.introspector.CachingRevocationAwareIntrospector;
import com.learn.api_gateway.service.InternalJwtService;
import com.learn.api_gateway.service.TokenRevocationService;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@EnableMethodSecurity(prePostEnabled = true) // for @PreAuthorize
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {
	
	public static final Duration CLOCK_SKEW = Duration.ofSeconds(30);

    @Value("${app.dev-mode:false}")
    private boolean devMode;
    
    @Value("${security.mtls.enabled:false}")
    private boolean mtlsEnabled;
    
    @Value("${app.oauth2.frontend-origin}")
    private String frontendOrigin;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(
            ServerHttpSecurity http,
            @Qualifier("cachingRevocationIntrospector") ReactiveOpaqueTokenIntrospector revocationAwareIntrospector,
            OpaqueTokenProperties opaqueProps) {

        // Derive introspection endpoint path for fine-grained access rules
        String introspectPath;
        try {
            String raw = opaqueProps.getOauth2().getOpaqueToken().getIntrospectionUri();
            introspectPath = (raw != null && !raw.isBlank()) ? URI.create(raw).getPath() : null;
        } catch (Exception ex) {
            log.warn("Invalid introspection URI in configuration", ex);
            introspectPath = null;
        }
        if (introspectPath == null || introspectPath.isBlank()) {
            introspectPath = "/realms/**/protocol/openid-connect/token/introspect";
        }
        final String finalIntrospectPath = introspectPath;
        // === Enforce HTTPS redirection (security best-practice) ===
        if (!devMode) {
            http.redirectToHttps(redirect -> redirect.httpsRedirectWhen(exchange -> true));
            log.info("HTTPS redirect ENABLED (devMode={}, mtlsEnabled={})", devMode, mtlsEnabled);
        } else {
            log.warn("Running in DEV mode — HTTPS redirect disabled");
        }
        
        http.securityMatcher(exchange -> {
            boolean blocked = Boolean.TRUE.equals(exchange.getAttribute("waf.blocked"));
            return blocked
                ? ServerWebExchangeMatcher.MatchResult.notMatch()
                : ServerWebExchangeMatcher.MatchResult.match();
        });
        
        // === Apply strong security headers ===
        http.headers(headers -> {
        	if (!devMode) {
                headers.hsts(hsts -> hsts
                    .maxAge(Duration.ofDays(365))
                    // includeSubDomains() REMOVED in WebFlux — only maxAge works now
                );
            } else {
                headers.hsts(ServerHttpSecurity.HeaderSpec.HstsSpec::disable);
                log.warn("Running in DEV mode — HSTS disabled");
            }
              headers.contentSecurityPolicy(csp -> csp.policyDirectives(
            		  "default-src 'none'; " +
            				  "script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/; " +
            				  "style-src 'self' 'nonce-{RANDOM_NONCE}'; " + 
                              "img-src 'self' data:; " +
                              "frame-src 'self' https://www.google.com/recaptcha/; " +
                              "connect-src 'self' " + frontendOrigin + "; " +
                              "object-src 'none'; " +
                              "frame-ancestors 'none'; " +
                              "form-action 'self'; base-uri 'self';"))
              	.referrerPolicy(ref -> ref.policy(ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.NO_REFERRER))
                .frameOptions(frame -> frame.mode(Mode.SAMEORIGIN))
                .xssProtection(xss -> xss.disable())
                .cache(cache -> cache.disable());
        });
        
//        http.cors(cors -> cors.configurationSource(exchange -> {
//	            CorsConfiguration config = new CorsConfiguration();
//	            config.setAllowedOrigins(List.of("https://your-frontend-domain.com"));
//	            config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
//	            config.setAllowedHeaders(List.of("*"));
//	            config.setAllowCredentials(true);
//	            config.setMaxAge(3600L);
//	            return config;
//	        }));
        
        // === CSRF off (REST API mode) ===
        http.csrf(ServerHttpSecurity.CsrfSpec::disable);
	        
        http.exceptionHandling(exceptions -> exceptions
        	    .authenticationEntryPoint((exchange, ex) -> {
        	        if (exchange.getResponse().isCommitted()) {
        	            log.debug("Security entry point called after commit – ignoring");
        	            return Mono.empty();
        	        }
        	        return Mono.error(ex);
        	    })
        	    .accessDeniedHandler((exchange, ex) -> {
        	        if (exchange.getResponse().isCommitted()) {
        	            log.debug("AccessDeniedHandler called after commit – ignoring");
        	            return Mono.empty();
        	        }
        	        return Mono.error(ex);
        	    })
        	);
        
	    http.authorizeExchange(exchanges -> exchanges
	            // Token introspection endpoint
	            .pathMatchers(HttpMethod.POST, finalIntrospectPath).hasAuthority("SCOPE_introspect")
	
	            // Public endpoints
	            .pathMatchers("/oauth-proxy/**").permitAll()
	            .pathMatchers("/auth/signup", "/auth/step-up","/auth/step-up/callback").permitAll()
	            .pathMatchers("/actuator/health", "/actuator/info","/realms/**").permitAll()
	            
	            // Internal service endpoints
	            .pathMatchers("/internal/revoke").hasAuthority("SCOPE_revoke:token")
	
	            // Business endpoints
	            .pathMatchers("/customer/**").hasRole("CUSTOMER")
	            .pathMatchers("/supplier/**").hasRole("SUPPLIER")
	
	            // Deny by default
	            .anyExchange().authenticated()
	        )
	        .oauth2ResourceServer(oauth2 ->
	        //below is for opaque Token, but for keycloak v.21+ not providing opaque token anymore
//	            oauth2.opaqueToken(token -> token.introspector(revocationAwareIntrospector))
		        oauth2.jwt(jwt -> 
		        //ver1
//		        jwt.jwkSetUri(
//		                    opaqueProps.getOauth2()
//		                               .getResourceserver()
//		                               .getJwkPublicKeyUri()
//		                )
		        //ver2 (Nimbus)
		        jwt.jwtDecoder(jwtDecoder(opaqueProps)))
	        );
	
	    // === Optional mTLS simulation for internal services ===
	    if (mtlsEnabled) {
	        // WebFlux doesn't support requiresChannel(), so we log + rely on gateway/network TLS
	        log.info("mTLS is enabled — ensure client certificates are validated at gateway or ingress level (Kubernetes mTLS).");
	    }
	
	    return http.build();
    }
    
    /**
     * Limits origins, methods, and headers to mitigate token replay or XSRF.
     */
//    @Bean
//    public CorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration config = new CorsConfiguration();
//        config.setAllowedOrigins(List.of(frontendOrigin));
//        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
//        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Trace-Id"));
//        config.setExposedHeaders(List.of("X-Trace-Id"));
//        config.setAllowCredentials(true);
//        config.setMaxAge(3600L);
//
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", config);
//        return source;
//    }
    
    @Bean
    public ReactiveOpaqueTokenIntrospector cachingRevocationIntrospector(
            ReactiveRedisTemplate<String, byte[]> principalCache,
            SecurityCacheProperties cacheProps,
            OpaqueTokenProperties opaqueProps,
            TokenRevocationService tokenRevocationService,
            ObjectMapper objectMapper) {

    	CachingRevocationAwareIntrospector introspector = new CachingRevocationAwareIntrospector(
                opaqueProps.getOauth2().getOpaqueToken().getIntrospectionUri(),
                opaqueProps.getOauth2().getOpaqueToken().getClientId(),
                opaqueProps.getOauth2().getOpaqueToken().getClientSecret(),
                principalCache,
                tokenRevocationService,
                cacheProps,
                opaqueProps,
                objectMapper
        );
        // Add JWS signature validation (if opaque tokens have embedded JWS)
        introspector.enableJwsSignatureValidation(true);

        // Enable automatic key rotation checks for HMAC secrets
        introspector.enableKeyRotationAwareness(true);
        
        introspector.setJwksUri(opaqueProps.getOauth2().getResourceserver().getJwkPublicKeyUri());

        return introspector;
    }
    
    /**
     * Ensures secure session cookie handling for WebFlux.
     * Required for OWASP compliance and SSO session safety.
     */
    @Bean
    public WebSessionIdResolver sessionIdResolver() {
        CookieWebSessionIdResolver resolver = new CookieWebSessionIdResolver();
        resolver.addCookieInitializer(builder -> builder
                .secure(true)         // only send cookie over HTTPS
                .httpOnly(true)       // prevent JavaScript access
                .sameSite("Strict")); // prevent CSRF via cross-site requests
        return resolver;
    }
    
    @Bean
    public ReactiveJwtDecoder jwtDecoder(OpaqueTokenProperties opaqueProps) {
    	String keycloakJwksUri = opaqueProps.getOauth2().getResourceserver().getJwkPublicKeyUri();
        NimbusReactiveJwtDecoder decoder =
                NimbusReactiveJwtDecoder.withJwkSetUri(keycloakJwksUri).build();
        
        Set<String> allowedAlgs = Set.of("RS256");

        OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefault(), // exp & nbf
                new JwtIssuerValidator(opaqueProps.getExpectedIssuer()),
                new JwtTimestampValidator(CLOCK_SKEW),
                new JwtClaimValidator<List<String>>("aud", aud -> aud != null && aud.contains(opaqueProps.getOauth2().getOpaqueToken().getExpectedAudience())),
//                new JwtClaimValidator<String>("typ", typ -> typ != null && typ.equals("Bearer")),
                jwt -> {
                	String alg = (String) jwt.getHeaders().get("alg");
                	if (!allowedAlgs.contains(alg)) {
                		return OAuth2TokenValidatorResult.failure(
                                new OAuth2Error("invalid_token", "Unsupported alg", null));
                	}
                    return OAuth2TokenValidatorResult.success();
                }
        );

        decoder.setJwtValidator(validator);
        return decoder;
    }
    
    @Bean
    public MeterBinder tokenCacheMetrics(ReactiveRedisTemplate<String, byte[]> redisTemplate) {
        return (MeterRegistry registry) -> {
            ReactiveRedisConnectionFactory factory = redisTemplate.getConnectionFactory();

            if (factory instanceof LettuceConnectionFactory lettuceFactory) {

                // 1. Redis Connection Configuration Present?
                Gauge.builder("gateway.redis.connection.configured", lettuceFactory,
                        lf -> lf.getStandaloneConfiguration() != null ? 1.0 : 0.0)
                    .description("1 if Redis connection configuration is present")
                    .register(registry);

                // 2. Check if SSL is enabled
                Gauge.builder("gateway.redis.ssl.enabled", lettuceFactory,
                        lf -> lf.isUseSsl() ? 1.0 : 0.0)
                    .description("1 if Redis SSL is enabled")
                    .register(registry);

                // 3. Expose Redis host:port hash as a unique id
                Gauge.builder("gateway.redis.connection.id", lettuceFactory,
                        lf -> (double) (lf.getHostName() + ":" + lf.getPort()).hashCode())
                    .description("Unique hash of Redis host:port for identification")
                    .register(registry);

                // 4. Simple connection alive check (ping)
                Gauge.builder("gateway.redis.connection.alive", redisTemplate,
                        rt -> {
                            try {
                                return rt.hasKey("healthcheck")
                                        .map(ok -> 1.0)
                                        .onErrorReturn(0.0)
                                        .blockOptional()
                                        .orElse(0.0);
                            } catch (Exception e) {
                                return 0.0;
                            }
                        })
                    .description("1 if Redis connection responds to PING, else 0")
                    .register(registry);
            }
        };
    }
}
