package com.travel.payment.exceptions;

public class ResourceNotFoundException extends RuntimeException {
	
	/**
	*
	*/
	private static final long serialVersionUID = 7605069051668836997L;
	 
	public ResourceNotFoundException(String message) {
	        super(message);
	    }

}
