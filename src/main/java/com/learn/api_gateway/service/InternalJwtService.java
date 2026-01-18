package com.learn.api_gateway.service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;

import com.learn.api_gateway.util.InternalJwtKeyProvider;

import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class InternalJwtService {
	@Value("${security.internal-jwt.issuer}")
    private String issuer;

    private final InternalJwtKeyProvider keyProvider;

    @Value("${security.internal-jwt.ttl-seconds:60}")
    private long ttlSeconds;

    public String issue(
            String audience,
            String userId,
            String sessionId,
            List<String> scopes,
            String email,
            String name,
            String userName,
            String givenName,
            String familyName) {
        Instant now = Instant.now();
        
        log.info("--------InternalJwtService ISSUED INTERNAL JWT aud={} sub={} scp={} email={} name={} userName={}",
                audience, userId, scopes,email, name, userName);
        
        InternalJwtKeyProvider.SigningKey active = keyProvider.activeKey();
        
        return Jwts.builder()
        		.setHeaderParam(Header.TYPE, Header.JWT_TYPE)
        		.setHeaderParam("kid", active.kid())
                .setIssuer(issuer)
                .setSubject(userId)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(ttlSeconds)))
                .claim("scp", scopes)
                .claim("sid", sessionId)
                .claim("aud", List.of(audience))
                .claim("email", email)
                .claim("name", name)
                .claim("preferred_username", userName)
                .claim("given_name", givenName)
                .claim("family_name", familyName)
                .setId(UUID.randomUUID().toString())
                .signWith(active.key(), SignatureAlgorithm.HS256)
                .compact();
       
    }
}
