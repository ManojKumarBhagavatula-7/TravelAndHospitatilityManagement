package com.cts.authentication.exception;


public class InvalidPasswordException extends RuntimeException {
    
    public InvalidPasswordException(String message) {
        super(message);
    }
}