package com.learn.api_gateway.util;

import java.net.InetAddress;

import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class IpUtil {
	private final EdgeIpCanonicalizer canon;
	
	public String normalizeIp(String ip) {
	    InetAddress addr = canon.parse(ip);
	    return canon.canonical(addr);
	}
}
