package com.learn.api_gateway.util;

public final class TraceConstants {
	public static final String TRACE_ID_HEADER = "X-Trace-Id";
    public static final String TRACE_ID_CONTEXT_KEY = "traceId";
    public static final String CLIENT_IP_CONTEXT_KEY="X-Client-Ip";
    public static final String USER_ID_CONTEXT_KEY="X-User-Id";

    private TraceConstants() {}
}
