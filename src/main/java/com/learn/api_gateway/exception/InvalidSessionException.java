package com.learn.api_gateway.exception;

public class InvalidSessionException extends RuntimeException{
	public InvalidSessionException() {
        super("Invalid session");
    }

    public InvalidSessionException(String message) {
        super(message);
    }

    public InvalidSessionException(String message, Throwable cause) {
        super(message, cause);
    }

}
