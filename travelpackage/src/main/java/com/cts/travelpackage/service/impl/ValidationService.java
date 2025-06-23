package com.cts.travelpackage.service.impl;

import java.util.Set;

import org.springframework.stereotype.Component;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Validator;

@Component
public class ValidationService {

	 private final Validator validator;
	 
	    public ValidationService(Validator validator) {
	        this.validator = validator;
	    }
	 
	    public <T> void validate(T object) {
	        Set<ConstraintViolation<T>> violations = validator.validate(object);
	      
	        if (!violations.isEmpty()) {
	  
	            throw new ConstraintViolationException(violations);
	        }
	    }
}
