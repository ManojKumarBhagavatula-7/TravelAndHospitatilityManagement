package com.travel.payment.exceptions;

public class DuplicatePaymentException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public DuplicatePaymentException(String message) {
		super(message);
	}
}
