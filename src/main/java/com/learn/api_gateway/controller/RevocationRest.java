package com.learn.api_gateway.controller;

import java.time.Duration;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.learn.api_gateway.dto.RevokeRequest;
import com.learn.api_gateway.service.TokenRevocationService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/internal/revoke")
public class RevocationRest {
	
	private final TokenRevocationService revocationService;

    /**
     * Internal use Revoke a token. Call via Keycloak SPI or service account with proper scope.
     *
     * Examples:
     *  - POST { "token": "eyJ..." , "expiresAt": 1700000000 }
     *  - POST { "token": "eyJ...", "ttlSeconds": 300 }
     *
     * If neither `ttlSeconds` nor `expiresAt` is provided, the revocation defaults
     * to 1 hour. This MUST be documented for clients — they should not assume
     * revocation is indefinite unless explicitly supported.
     */
    @PostMapping
    @PreAuthorize("hasAuthority('SCOPE_revoke:token')") // only service account with this scope can call
    public Mono<ResponseEntity<Void>> revoke(@RequestBody RevokeRequest req) {
        if (req == null || req.token() == null || req.token().isBlank()) {
            return Mono.just(ResponseEntity.badRequest().build());
        }

        log.info("Revocation requested for token [prefix={}] by caller",
                maskToken(req.token()));

        if (req.ttlSeconds() != null && req.ttlSeconds() > 0) {
            return revocationService.revokeToken(req.token(), Duration.ofSeconds(req.ttlSeconds()))
                    .thenReturn(ResponseEntity.ok().<Void>build());
        }

        if (req.expiresAt() != null && req.expiresAt() > 0) {
            return revocationService.revokeTokenAtExpiry(req.token(), req.expiresAt())
                    .thenReturn(ResponseEntity.ok().<Void>build());
        }

        // Default TTL = 1 hour
        return revocationService.revokeToken(req.token(), Duration.ofHours(1))
                .thenReturn(ResponseEntity.ok().<Void>build());
    }

    /**
     * Mask token for logs to avoid leaking sensitive values.
     */
    private String maskToken(String token) {
        if (token.length() <= 10) {
            return "****";
        }
        return token.substring(0, 5) + "..." + token.substring(token.length() - 5);
    }
}
