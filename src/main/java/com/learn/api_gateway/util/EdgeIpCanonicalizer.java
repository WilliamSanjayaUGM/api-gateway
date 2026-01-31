package com.learn.api_gateway.util;

import java.net.InetAddress;

import org.springframework.stereotype.Component;

@Component
public final class EdgeIpCanonicalizer {

    public InetAddress parse(String ip) {
        try {
            return InetAddress.getByName(ip);
        } catch (Exception e) {
            return null;
        }
    }

    public String canonical(InetAddress addr) {
        if (addr == null) return null;

        if (addr.isLoopbackAddress() || addr.isAnyLocalAddress()) {
            return "127.0.0.1";
        }

        return addr.getHostAddress();
    }

    public boolean isNonRoutable(InetAddress addr) {
        if (addr == null) return true;

        return addr.isLoopbackAddress()
            || addr.isAnyLocalAddress()
            || addr.isSiteLocalAddress()
            || addr.isLinkLocalAddress();
    }
}
