package com.learn.api_gateway.filter;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.learn.api_gateway.dto.HijackRisk;
import com.learn.api_gateway.exception.InvalidSessionException;
import com.learn.api_gateway.resolver.ClientTypeResolver;
import com.learn.api_gateway.resolver.ClientTypeResolver.ClientType;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Filter which also protection against session hijacking
 */
@Component
@RequiredArgsConstructor
@Slf4j
@Order(-720) // Runs JUST BEFORE Spring Security AUTHENTICATION (-100)
public class SessionToBearerTokenFilter implements WebFilter{
	private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
    private final ClientTypeResolver clientTypeResolver;
    private final ObjectMapper objectMapper;

    @Value("${security.session.cookie-name:API-SESSION}")
    private String sessionCookieName;

    @Value("${security.session.sessionTtlSeconds}")
    private long sessionTtlSeconds;

    @Value("${app.oauth2.frontend-origin}")
    private String frontendUri;

    /* ======================= POLICY ======================= */
    private static final int MAX_SESSIONS_PER_USER   = 5;
    private static final int MAX_SESSIONS_PER_DEVICE = 1;
    private static final int MAX_SESSIONS_PER_IP     = 2;

    private static final String SESSION_PREFIX = "session:";
    private static final String MOBILE_PREFIX  = "mobile:access:";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    	 String path = exchange.getRequest().getPath().value();
    	 if (path.startsWith("/auth/") || path.startsWith("/realms/") ) {
    		 log.info("----SessionToBearerTokenFilter pas through with path {}",path);
    		 return chain.filter(exchange);
    	 }
    	    
        /* =======================
         * MOBILE FLOW
         * ======================= */
        if (clientTypeResolver.resolve(exchange) == ClientType.MOBILE) {

            String auth = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (auth == null || !auth.startsWith("Bearer mob_")) {
                return chain.filter(exchange);
            }

            String mobileToken = auth.substring(7);
            String redisKey = MOBILE_PREFIX + mobileToken;
            String deviceId = exchange.getRequest().getHeaders().getFirst("X-Device-Id");

            return reactiveRedisTemplate.opsForValue()
                    .get(redisKey)
                    .switchIfEmpty(Mono.error(new InvalidSessionException("mobile session missing")))
                    .flatMap(raw -> {

                        final MobileSessionRecord session;
                        try {
                            session = objectMapper.readValue(raw, MobileSessionRecord.class);
                        } catch (Exception e) {
                            return reject(exchange);
                        }

                        if (!Objects.equals(session.deviceId(), deviceId)) {
                            log.warn("MOBILE_DEVICE_MISMATCH user={}", session.userId());
                            return reject(exchange);
                        }

                        return validateMobileSessionVersion(session)
                                .flatMap(valid -> {
                                    ServerHttpRequest mutated = exchange.getRequest()
                                            .mutate()
                                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + valid.accessToken())
                                            .build();
                                    return chain.filter(exchange.mutate().request(mutated).build());
                                });
                    })
                    .onErrorResume(InvalidSessionException.class, ex -> reject(exchange));
        }

        /* =======================
         * BROWSER SESSION FLOW
         * ======================= */
        HttpCookie cookie = exchange.getRequest().getCookies().getFirst(sessionCookieName);
        if (cookie == null) {
            return chain.filter(exchange);
        }

        final String sessionId = cookie.getValue();
        final String redisKey  = SESSION_PREFIX + sessionId;
        final String stepUpKey = SESSION_PREFIX + sessionId + ":stepup";

        return reactiveRedisTemplate.opsForValue()
                .get(redisKey)
                .switchIfEmpty(Mono.error(new InvalidSessionException("Session not found")))
                .flatMap(raw -> {

                    final SessionRecord session;
                    try {
                        session = objectMapper.readValue(raw, SessionRecord.class);
                    } catch (Exception e) {
                        return invalidateAndReject(exchange, sessionId);
                    }

                    return validateSessionVersion(sessionId, session)
                            .flatMap(validSession ->

                                /* ===============================
                                 * STEP-UP FREEZE CHECK
                                 * =============================== */
                                reactiveRedisTemplate.hasKey(stepUpKey)
                                        .flatMap(frozen -> {
                                            if (Boolean.TRUE.equals(frozen)) {
                                                return isStepUpResolved(
                                                        sessionId,
                                                        validSession.sessionVersion()
                                                ).flatMap(resolved ->
                                                        resolved
                                                                ? continueSession(exchange, chain, validSession, sessionId) // FIX
                                                                : redirectStepUpOnly(exchange)
                                                );
                                            }

                                            return evaluateSessionRisk(
                                                    exchange,
                                                    chain,
                                                    validSession,
                                                    sessionId
                                            );
                                        })
                            );
                })
                .onErrorResume(
                        InvalidSessionException.class,
                        ex -> invalidateAndReject(exchange, sessionId)
                );
    }
    
    private Mono<Void> evaluateSessionRisk(
            ServerWebExchange exchange,
            WebFilterChain chain,
            SessionRecord session,
            String sessionId) {
        String currentIp = Optional.ofNullable(exchange.getAttribute(ClientIpFilter.ATTR_CLIENT_IP))
                .map(Object::toString)
                .orElse("unknown");

        String currentUaHash = hashUa(
                exchange.getRequest().getHeaders().getFirst(HttpHeaders.USER_AGENT)
        );

        /* === MAX AGE === */
        if (session.issuedAt() != null &&
            session.issuedAt().isBefore(Instant.now().minus(Duration.ofHours(12)))) {
            return invalidateAndReject(exchange, sessionId);
        }

        /* === DEVICE BINDING === */
        DeviceFingerprint stored  = session.deviceFingerprint();
        DeviceFingerprint current = resolveDeviceFingerprint(exchange);

        if (stored != null && stored.deviceId() != null) {
            if (current.deviceId() == null) {
                return triggerStepUp(exchange, sessionId, HijackRisk.MEDIUM);
            }
            if (!Objects.equals(stored.deviceId(), current.deviceId())) {
                return triggerStepUp(exchange, sessionId, HijackRisk.HIGH);
            }
        }

        /* === CONCURRENCY LIMITS === */
        String userKey   = userSessionsKey(session.userId());
        String deviceKey = deviceSessionsKey(
                current.deviceId() != null ? current.deviceId() : "unknown"
        );
        String ipKey     = ipSessionsKey(currentIp);

        return Mono.zip(
                reactiveRedisTemplate.opsForSet().size(userKey),
                reactiveRedisTemplate.opsForSet().size(deviceKey),
                reactiveRedisTemplate.opsForSet().size(ipKey)
        ).flatMap(counts -> {

            if (counts.getT1() > MAX_SESSIONS_PER_USER ||
                counts.getT2() > MAX_SESSIONS_PER_DEVICE ||
                counts.getT3() > MAX_SESSIONS_PER_IP) {
                return triggerStepUp(exchange, sessionId, HijackRisk.MEDIUM);
            }

            HijackRisk risk = assessHijackRisk(session, currentIp, currentUaHash);

            if (risk == HijackRisk.HIGH) {
                return triggerStepUp(exchange, sessionId, HijackRisk.HIGH);
            }

            if (risk == HijackRisk.MEDIUM) {
                return isStepUpResolved(sessionId, session.sessionVersion())
                        .flatMap(resolved ->
                                resolved
                                        ? continueSession(exchange, chain, session, sessionId)
                                        : triggerStepUp(exchange, sessionId, HijackRisk.MEDIUM)
                        );
            }

            return continueSession(exchange, chain, session, sessionId);
        });
    }
    
    private Mono<Void> continueSession(
            ServerWebExchange exchange,
            WebFilterChain chain,
            SessionRecord session,
            String sessionId
    ) {
    	log.info("-----Go to continueSession SessionToBearerToken session_token:{}", session.token());
        ServerHttpRequest mutated = exchange.getRequest()
                .mutate()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + session.token())
                .build();

//        return reactiveRedisTemplate.opsForValue()
//                .set(
//                        SESSION_PREFIX + sessionId,
//                        serialize(session),
//                        Duration.ofSeconds(sessionTtlSeconds)
//                )
//                .then(chain.filter(exchange.mutate().request(mutated).build()));
        ServerWebExchange mutatedExchange =
                exchange.mutate().request(mutated).build();

        // Fire-and-forget Redis refresh (DO NOT block request pipeline)
        reactiveRedisTemplate.opsForValue()
                .set(
                        SESSION_PREFIX + sessionId,
                        serialize(session),
                        Duration.ofSeconds(sessionTtlSeconds)
                )
                .subscribe(
                    null,
                    ex -> log.warn("Redis refresh failed sessionId={}", sessionId, ex)
                );

        return chain.filter(mutatedExchange);
    }
    
    private Mono<Void> redirectStepUpOnly(ServerWebExchange exchange) {
        ServerHttpResponse resp = exchange.getResponse();
        if (resp.isCommitted()) return Mono.empty();

        resp.setStatusCode(HttpStatus.SEE_OTHER);
        resp.getHeaders().set(
                HttpHeaders.LOCATION,
                frontendUri + "/auth/step-up?reason=session_verification"
        );
        return resp.setComplete();
    }
    
    private String serialize(Object o) {
        try {
            return objectMapper.writeValueAsString(o);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
    
    private Mono<MobileSessionRecord> validateMobileSessionVersion(
            MobileSessionRecord record) {

        String versionKey = "user:" + record.userId() + ":session-version";

        return reactiveRedisTemplate.opsForValue()
            .get(versionKey)
            .flatMap(v -> {
                if (v == null || Integer.parseInt(v) != record.sessionVersion()) {
                    return Mono.error(new InvalidSessionException("mobile version mismatch"));
                }
                return Mono.just(record);
            });
    }
    
    private Mono<Void> reject(ServerWebExchange exchange) {
    	String auth = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
    	Mono<Void> invalidate = Mono.empty();
    	
    	if (auth != null && auth.startsWith("Bearer mob_")) {
            String mobileToken = auth.substring(7);
            String redisKey = MOBILE_PREFIX + mobileToken;

            invalidate = reactiveRedisTemplate
                    .delete(redisKey)
                    .doOnNext(deleted ->
                            log.warn("Invalidated mobile session token={}", mobileToken))
                    .then();
        }

        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().remove(HttpHeaders.AUTHORIZATION);

        return invalidate.then(exchange.getResponse().setComplete());
    }

    private String hashUa(String ua) {
        if (ua == null) return "unknown";
        return DigestUtils.sha256Hex(ua);
    }
    
    private Mono<SessionRecord> validateSessionVersion(
            String sessionId,
            SessionRecord record) {

        String versionKey = "user:" + record.userId() + ":session-version";

        return reactiveRedisTemplate.opsForValue()
            .get(versionKey)
            .flatMap(currentVersion -> {

                if (currentVersion == null) {
                    log.warn("Missing session-version for user={}, invalidating session={}",
                            record.userId(), sessionId);

                    return invalidateSession(sessionId);
                }

                int activeVersion;
                try {
                    activeVersion = Integer.parseInt(currentVersion);
                } catch (NumberFormatException ex) {
                    log.error("Corrupted session-version for user={}", record.userId(), ex);
                    return invalidateSession(sessionId);
                }

                if (activeVersion != record.sessionVersion()) {
                    log.warn("Session version mismatch for user={} session={} stored={} active={}",
                            record.userId(),
                            sessionId,
                            record.sessionVersion(),
                            activeVersion);

                    return invalidateSession(sessionId);
                }

                return Mono.just(record);
            });
    }
    
    private Mono<Void> invalidateAndReject(ServerWebExchange exchange, String sessionId) {
    	return reactiveRedisTemplate.opsForValue()
                .get(SESSION_PREFIX + sessionId)
                .flatMap(raw -> {
                    try {
                        SessionRecord record =
                                objectMapper.readValue(raw, SessionRecord.class);

                        String deviceId =
                                record.deviceFingerprint() != null
                                        ? record.deviceFingerprint().deviceId()
                                        : "unknown";

                        return Mono.when(
                                reactiveRedisTemplate.delete(SESSION_PREFIX + sessionId),
                                reactiveRedisTemplate.opsForSet()
                                        .remove(userSessionsKey(record.userId()), sessionId),
                                reactiveRedisTemplate.opsForSet()
                                        .remove(deviceSessionsKey(deviceId), sessionId),
                                reactiveRedisTemplate.opsForSet()
                                        .remove(ipSessionsKey(record.ip()), sessionId)
                        );
                    } catch (Exception e) {
                        return reactiveRedisTemplate.delete(SESSION_PREFIX + sessionId);
                    }
                })
                .then(Mono.defer(() -> {
                    ResponseCookie expired = ResponseCookie.from(sessionCookieName, "")
                            .path("/")
                            .maxAge(0)
                            .httpOnly(true)
                            .secure(true)
                            .sameSite("Strict")
                            .build();
                    exchange.getResponse().addCookie(expired);
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }));
    }
    
    private Mono<SessionRecord> invalidateSession(String sessionId) {
        return reactiveRedisTemplate.delete("session:" + sessionId)
                .then(Mono.error(new InvalidSessionException("Session invalidated")));
    }
    
    private HijackRisk assessHijackRisk(
            SessionRecord session,
            String currentIp,
            String currentUaHash) {

        if (!Objects.equals(session.uaHash(), currentUaHash)) {
        	log.info("------SessionToBearerToken assessHijackRisk uaHash {} currentUaHash {} HIGH", session.uaHash(), currentUaHash);
            return HijackRisk.HIGH;
        }
        if (!Objects.equals(session.ip(), currentIp)) {
        	log.info("------SessionToBearerToken assessHijackRisk sessionIp {} currentIp {} MEDIUM", session.ip(), currentIp);
            return HijackRisk.MEDIUM;
        }
        log.info("------SessionToBearerToken assessHijackRisk LOW");
        return HijackRisk.LOW;
    }
    
    /**
     * MEDIUM → freeze + step-up
     * HIGH → invalidate immediately
     */
    private Mono<Void> triggerStepUp(
            ServerWebExchange exchange,
            String sessionId,
            HijackRisk risk) {

        if (risk == HijackRisk.HIGH) {
            log.warn("HIGH_RISK_HIJACK sessionId={}, forcing logout", sessionId);
            return invalidateAndReject(exchange, sessionId);
        }

        if (risk == HijackRisk.MEDIUM) {
            log.warn("MEDIUM_RISK_HIJACK sessionId={}, triggering step-up", sessionId);

            String stepUpKey = SESSION_PREFIX + sessionId + ":stepup";

            return reactiveRedisTemplate.opsForValue()
                    .set(stepUpKey, "REQUIRED", Duration.ofMinutes(5))
                    .then(Mono.defer(() -> {

                        ServerHttpResponse resp = exchange.getResponse();
                        if (resp.isCommitted()) {
                            return Mono.empty();
                        }

                        resp.setStatusCode(HttpStatus.SEE_OTHER);
                        resp.getHeaders().set(
                                HttpHeaders.LOCATION,
                                frontendUri + "/auth/step-up?reason=session_verification"
                        );
                        return resp.setComplete();
                    }));
        }

        // LOW risk → continue
        return Mono.empty();
    }
    
    private DeviceFingerprint resolveDeviceFingerprint(ServerWebExchange exchange) {
    	return new DeviceFingerprint(
                exchange.getRequest().getHeaders().getFirst("X-Device-Id"),
                hashUa(exchange.getRequest().getHeaders().getFirst(HttpHeaders.USER_AGENT)),
                exchange.getRequest().getHeaders().getFirst("X-Platform"),
                exchange.getRequest().getHeaders().getFirst("X-App-Version")
        );
    }
    
    private Mono<Boolean> isStepUpResolved(
            String sessionId,
            int sessionVersion) {

    	String resolvedKey = "session:" + sessionId + ":stepup:resolved";

        return reactiveRedisTemplate.opsForValue()
                .get(resolvedKey)
                .map(storedVersion ->
                        Objects.equals(storedVersion, String.valueOf(sessionVersion))
                )
                .defaultIfEmpty(false);
    }
    
    private String userSessionsKey(String userId) {
        return "user:" + userId + ":sessions";
    }

    private String deviceSessionsKey(String deviceId) {
        return "device:" + deviceId + ":sessions";
    }

    private String ipSessionsKey(String ip) {
        return "ip:" + ip + ":sessions";
    }

    /* === Immutable session record === */
    public record SessionRecord(
            String token,
            String userId,
            String ip,
            String uaHash,
            int sessionVersion,
            DeviceFingerprint deviceFingerprint,
            Instant issuedAt,
            Instant lastSeenAt
    ) {}
    
    public record MobileSessionRecord(
            String accessToken,   // real Keycloak JWT
            String userId,
            String sessionId,
            String deviceId,      // from header
            String ip,
            int sessionVersion
    ) {}
    
    public record DeviceFingerprint(
            String deviceId,
            String uaHash,
            String platform,
            String appVersion
    ) {}
}
