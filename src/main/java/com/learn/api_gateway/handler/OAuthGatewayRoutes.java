package com.learn.api_gateway.handler;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

@Configuration
public class OAuthGatewayRoutes {
	
	@Bean
	public RouterFunction<ServerResponse> oauthRoutes(OAuthLoginHandler handler) {
	    return RouterFunctions.route()
	        .POST("/oauth-proxy/login", handler::login)
	        .GET("/oauth-proxy/callback", handler::callback)
	        .build();
	}
}
