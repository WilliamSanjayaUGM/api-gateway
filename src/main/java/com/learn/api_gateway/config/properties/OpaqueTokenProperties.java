package com.learn.api_gateway.config.properties;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import jakarta.annotation.PostConstruct;
import lombok.Data;

@Configuration
@ConfigurationProperties(prefix = "security")
@Data
@Validated
public class OpaqueTokenProperties {
	private Oauth2 oauth2 = new Oauth2();

    private boolean autoRefreshTrustedRoles = false;
    private Set<String> normalizedTrustedRoles = Set.of();
    private String keycloakRolesEndpoint;
    private Set<String> excludedPaths = Set.of();

    @PostConstruct
    public void normalizeRoles() {
    	Set<String> trustedRoles = oauth2.getOpaqueToken().getTrustedRoles();
        this.normalizedTrustedRoles = (trustedRoles == null) ? Set.of() :
                trustedRoles.stream()
                        .filter(r -> r != null && !r.isBlank())
                        .map(String::trim)
                        .map(r -> r.toUpperCase(Locale.ROOT))
                        .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                        .collect(Collectors.toSet());
        
        this.excludedPaths = oauth2.getExcludedPaths();
    }

    public String getExpectedIssuer() {
    	String expectedIssuer=oauth2.getOpaqueToken().getExpectedIssuer();
        if (expectedIssuer == null) return null;
        String v = expectedIssuer.trim();
        if (v.endsWith("/")) v = v.substring(0, v.length() - 1);
        return v;
    }
    
    @Data
    public static class Oauth2 {
        private ResourceServer resourceserver = new ResourceServer();
        private OpaqueToken opaqueToken = new OpaqueToken();
        private Set<String> excludedPaths = new HashSet<>();

        @Data
        public static class ResourceServer {
            private String jwkPublicKey;
            private String jwkPublicKeyUri;
        }

        @Data
        public static class OpaqueToken {
            private String introspectionUri;
            private String clientId;
            private String clientSecret;
            private String expectedAudience;
            private String expectedIssuer;
            private Set<String> trustedRoles;
            private boolean autoRefreshTrustedRoles;
            private String keycloakRolesEndpoint;
        }
    }

    /**
     * Decode the PEM-encoded RSA public key into RSAPublicKey
     */
    public RSAPublicKey publicKey() {
        try {
        	String jwkPublicKey = oauth2.getResourceserver().getJwkPublicKey();
            if (jwkPublicKey == null || jwkPublicKey.isBlank()) {
                throw new IllegalStateException("Missing security.oauth2.resourceserver.jwk-public-key");
            }

            String key = jwkPublicKey
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");

            byte[] decoded = Base64.getDecoder().decode(key);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Invalid JWK public key", e);
        }
    }
}
