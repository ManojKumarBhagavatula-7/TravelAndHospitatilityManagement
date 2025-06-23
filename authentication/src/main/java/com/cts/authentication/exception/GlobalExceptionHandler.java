package com.cts.authentication.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.request.WebRequest; // Import WebRequest for path details

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Global exception handler for the application. This class uses Spring's
 * {@code @ControllerAdvice} to provide centralized exception handling across
 * all {@code @RequestMapping} methods. It catches specific custom exceptions
 * and generic {@code Exception}s, returning standardized error responses.
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /**
     * Helper method to create a consistent error response map.
     *
     * @param status The HTTP status to return.
     * @param message The error message.
     * @param request The current web request, used to extract path details.
     * @return A map containing error details such as timestamp, status, error type, and message.
     */
    private Map<String, Object> createErrorResponse(HttpStatus status, String message, WebRequest request) {
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("timestamp", LocalDateTime.now());
        errorDetails.put("status", status.value());
        errorDetails.put("error", status.getReasonPhrase());
        errorDetails.put("message", message);
        errorDetails.put("path", request.getDescription(false).replace("uri=", "")); // Clean up path for better readability
        logger.debug("Created error response for path {}: Status={}, Message='{}'", errorDetails.get("path"), status.value(), message);
        return errorDetails;
    }

    /**
     * Handles {@link UserNotFoundException}s, returning an HTTP 404 Not Found status.
     *
     * @param ex The {@code UserNotFoundException} that was thrown.
     * @param request The current web request.
     * @return A {@link ResponseEntity} with an error response body and HTTP 404 status.
     */
    @ExceptionHandler(UserNotFoundException.class)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> handleUserNotFound(UserNotFoundException ex, WebRequest request) {
        logger.warn("UserNotFoundException caught: {} | Path: {}", ex.getMessage(), request.getDescription(false));
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(createErrorResponse(HttpStatus.NOT_FOUND, ex.getMessage(), request));
    }

    /**
     * Handles {@link InvalidPasswordException}s, returning an HTTP 401 Unauthorized status.
     *
     * @param ex The {@code InvalidPasswordException} that was thrown.
     * @param request The current web request.
     * @return A {@link ResponseEntity} with an error response body and HTTP 401 status.
     */
    @ExceptionHandler(InvalidPasswordException.class)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> handleInvalidPassword(InvalidPasswordException ex, WebRequest request) {
        logger.warn("InvalidPasswordException caught: {} | Path: {}", ex.getMessage(), request.getDescription(false));
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(createErrorResponse(HttpStatus.UNAUTHORIZED, ex.getMessage(), request));
    }

    /**
     * Handles {@link ApiException}s, returning an HTTP 400 Bad Request status.
     * This is a general-purpose exception for client-side errors.
     *
     * @param ex The {@code ApiException} that was thrown.
     * @param request The current web request.
     * @return A {@link ResponseEntity} with an error response body and HTTP 400 status.
     */
    @ExceptionHandler(ApiException.class)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> handleApiException(ApiException ex, WebRequest request) {
        logger.warn("ApiException caught: {} | Path: {}", ex.getMessage(), request.getDescription(false));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(createErrorResponse(HttpStatus.BAD_REQUEST, ex.getMessage(), request));
    }

    /**
     * Handles {@link MethodArgumentNotValidException}s, which occur when
     * {@code @Valid} annotation fails validation on a controller method argument.
     * Returns an HTTP 400 Bad Request with detailed validation error messages.
     *
     * @param ex The {@code MethodArgumentNotValidException} that was thrown.
     * @param request The current web request.
     * @return A {@link ResponseEntity} with an error response body and HTTP 400 status,
     * including specific field validation errors.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(MethodArgumentNotValidException ex, WebRequest request) {
        String detailedMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining("; "));

        logger.warn("MethodArgumentNotValidException caught: Validation failed for fields: {} | Path: {}", detailedMessage, request.getDescription(false));

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(createErrorResponse(HttpStatus.BAD_REQUEST, "Validation failed: " + detailedMessage, request));
    }

    /**
     * Generic exception handler for any other unhandled exceptions.
     * This acts as a fallback and returns an HTTP 500 Internal Server Error.
     * It logs the full stack trace for debugging but provides a generic message to the client
     * to avoid exposing sensitive internal information in production.
     *
     * @param ex The {@code Exception} that was thrown.
     * @param request The current web request.
     * @return A {@link ResponseEntity} with a generic error response body and HTTP 500 status.
     */
    @ExceptionHandler(Exception.class)
    @ResponseBody
    public ResponseEntity<Map<String, Object>> handleGenericException(Exception ex, WebRequest request) {
        logger.error("Unhandled Exception caught: {} | Path: {}", ex.getMessage(), request.getDescription(false), ex);
        // Do not expose internal error messages in production for generic exceptions
        String errorMessage = "An unexpected error occurred. Please try again later.";
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, errorMessage, request));
    }
}