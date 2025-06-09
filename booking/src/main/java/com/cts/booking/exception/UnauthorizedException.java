package com.cts.booking.exception;

//when user is not authorized
public class UnauthorizedException extends RuntimeException{
	
	public UnauthorizedException(String message) {
		super(message);
	}

}