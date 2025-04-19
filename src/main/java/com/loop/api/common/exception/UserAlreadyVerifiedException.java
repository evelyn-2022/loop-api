package com.loop.api.common.exception;

public class UserAlreadyVerifiedException extends RuntimeException {
	public UserAlreadyVerifiedException(String message) {
		super(message);
	}
}