package com.learn.api_gateway.dto;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CaptchaResponse(boolean success,
		String challengeTs,
		String hostname,
		float score,
		String action,
		@JsonProperty("error-codes") List<String> errorCodes) {

}
