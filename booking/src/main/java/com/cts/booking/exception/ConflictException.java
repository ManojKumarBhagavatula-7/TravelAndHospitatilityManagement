package com.cts.booking.exception;

//when entry already exists
public class ConflictException extends RuntimeException{
	
	public ConflictException(String message) {
		super(message);
	}

}