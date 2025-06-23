package com.cts.SupportTicket;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.cts.SupportTicket.exception.EntityNotFoundException;

class EntityNotFoundExceptionTest {

    @Test
    void testMessageConstructor() {
        String message = "Custom error message";
        EntityNotFoundException exception = new EntityNotFoundException(message);
        assertEquals(message, exception.getMessage());
    }

    @Test
    void testEntityNameAndIdConstructor() {
        String entityName = "Ticket";
        int id = 101;
        EntityNotFoundException exception = new EntityNotFoundException(entityName, id);
        assertEquals("Ticket with ID 101 not found.", exception.getMessage());
    }

    @Test
    void testEntityNameAndIdentifierConstructor() {
        String entityName = "User";
        String identifier = "john.doe@example.com";
        EntityNotFoundException exception = new EntityNotFoundException(entityName, identifier);
        assertEquals("User with identifier 'john.doe@example.com' not found.", exception.getMessage());
    }
}
