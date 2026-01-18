package com.learn.api_gateway.dto;

public record LoginRequest(String email,String password, String recaptchaToken) {

}
