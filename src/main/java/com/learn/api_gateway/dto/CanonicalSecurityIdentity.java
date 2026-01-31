package com.learn.api_gateway.dto;

public record CanonicalSecurityIdentity(String scheme,
	    String ip,
	    String action,
	    String path,
	    String clientId,
	    String username,
	    long epochMinute) {

}
