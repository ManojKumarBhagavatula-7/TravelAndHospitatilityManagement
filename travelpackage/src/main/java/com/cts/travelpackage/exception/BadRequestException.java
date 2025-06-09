package com.cts.travelpackage.exception;

//for invalid inputs
public class BadRequestException extends RuntimeException{
	
	public BadRequestException(String message) {
		super(message);
	}

}
