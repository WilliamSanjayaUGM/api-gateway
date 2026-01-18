package com.learn.api_gateway.util;

import lombok.experimental.UtilityClass;

@UtilityClass
public class BodySafetyLimits {
	public static final long MAX_RAW_BYTES        = 512 * 1024;        // 512 KB
    public static final long MAX_COMPRESSED_BYTES = 5L * 1024 * 1024;  // 5 MB
    public static final long MAX_INFLATED_BYTES   = 50L * 1024 * 1024; // 50 MB
    public static final int  MAX_ZIP_ENTRIES      = 5_000;
}
