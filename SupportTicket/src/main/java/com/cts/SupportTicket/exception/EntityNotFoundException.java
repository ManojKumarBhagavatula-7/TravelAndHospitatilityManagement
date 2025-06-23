package com.cts.SupportTicket.exception;

public class EntityNotFoundException extends Exception {
	private static final long serialVersionUID = 1L;

	public EntityNotFoundException(String message) {
		super(message);
	}

	public EntityNotFoundException(String entityName, int id) {
		super(entityName + " with ID " + id + " not found.");
	}

	public EntityNotFoundException(String entityName, String identifier) {
		super(entityName + " with identifier '" + identifier + "' not found.");
	}

}
