package com.learn.api_gateway.dto;

public enum CaptchaResult {
	PASSED,
    INVALID,
    RATE_LIMITED,
    PROVIDER_ERROR
}
