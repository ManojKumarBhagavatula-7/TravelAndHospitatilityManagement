package com.cts.travelpackage.exception;

//when user is not authorized
public class UnauthorizedException extends RuntimeException{
	
	public UnauthorizedException(String message) {
		super(message);
	}

}