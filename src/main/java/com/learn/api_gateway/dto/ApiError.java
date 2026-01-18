package com.learn.api_gateway.dto;

import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor(staticName = "of")
public class ApiError {
	private Instant timestamp;
    private int status;
    private String error;
    private String message;
    private String traceId;
}
