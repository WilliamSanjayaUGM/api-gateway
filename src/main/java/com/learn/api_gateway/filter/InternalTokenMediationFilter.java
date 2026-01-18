package com.learn.api_gateway.filter;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.NettyRoutingFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.learn.api_gateway.service.InternalJwtService;
import com.learn.api_gateway.util.TraceConstants;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Filter to issued iat to downstream-service
 */
@RequiredArgsConstructor
@Slf4j
@Component
public class InternalTokenMediationFilter implements GlobalFilter, Ordered{

	private final InternalJwtService internalJwtService;
	private final ReactiveJwtDecoder jwtDecoder;
	
	@Override
    public int getOrder() {
		// MUST run before routing
        return NettyRoutingFilter.ORDER - 1;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);

        if (route == null ||
            !"required".equals(route.getMetadata().get("internal-auth"))) {
            return chain.filter(exchange);
        }
        
        log.info("-------InternalTokenMediationFilter rewrite AUTH header is running--------");        
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
        	exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        
        return jwtDecoder.decode(authHeader.substring(7))
        	    .flatMap(externalJwt -> {
        	    	String traceId = Optional.ofNullable(exchange.getAttribute(TraceConstants.TRACE_ID_CONTEXT_KEY))
        	                .map(Object::toString)
        	                .orElse(UUID.randomUUID().toString());
        	    	List<String> scopes = resolveScopes(externalJwt);
        	    	String internalJwt = internalJwtService.issue(
        	                route.getId(),                 // aud
        	                externalJwt.getSubject(),      // sub
        	                externalJwt.getClaimAsString("sid"),
        	                scopes,
        	                externalJwt.getClaimAsString("email"),
        	                externalJwt.getClaimAsString("name"),
        	                externalJwt.getClaimAsString("preferred_username"),
        	                externalJwt.getClaimAsString("given_name"),
        	                externalJwt.getClaimAsString("family_name")
        	        );

        	        ServerHttpRequest mutated = exchange.getRequest()
        	                .mutate()
        	                .headers(h -> {
        	                    h.remove(HttpHeaders.AUTHORIZATION);
        	                    h.add(HttpHeaders.AUTHORIZATION, "Bearer " + internalJwt);
        	                })
        	                .build();

        	        log.info("--- InternalTokenMediationFilter Internal JWT issued for route={}, with intJwt={}", route.getId(), internalJwt);

        	        return chain.filter(exchange.mutate().request(mutated).build());
        	    })
        	    .onErrorResume(ex -> {
        	        log.warn("--- InternalTokenMediationFilter External JWT validation failed", ex);
        	        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        	        return exchange.getResponse().setComplete();
        	    });
    }
    
    private List<String> resolveScopes(Jwt externalJwt) {

        // Prefer scp if present (some IdPs use it)
        List<String> scp = externalJwt.getClaimAsStringList("scp");
        if (scp != null && !scp.isEmpty()) {
            return scp;
        }

        // Fallback to OIDC "scope" (space-delimited string)
        String scope = externalJwt.getClaimAsString("scope");
        if (scope != null && !scope.isBlank()) {
            return Arrays.stream(scope.split(" "))
                    .filter(s -> !s.isBlank())
                    .distinct()
                    .toList();
        }

        // Never return null
        return List.of();
    }

}
