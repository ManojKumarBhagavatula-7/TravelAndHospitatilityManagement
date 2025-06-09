package com.cts.travelpackage.exception;

//when entry already exists
public class ConflictException extends RuntimeException{
	
	public ConflictException(String message) {
		super(message);
	}

}