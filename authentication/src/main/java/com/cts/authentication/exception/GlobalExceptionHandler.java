package com.cts.authentication.exception;

import com.cts.authentication.response.RestResponse; // Import the new RestResponse class
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.request.WebRequest;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Global exception handler for the authentication service.
 * This class intercepts specific exceptions thrown by controllers or services
 * and maps them to appropriate HTTP responses with a standardized {@link RestResponse} body.
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /**
     * Helper method to create a consistent error {@link ResponseEntity} using the {@link RestResponse} format.
     * It packages the error message into a Map for the 'data' payload.
     *
     * @param status  The HTTP status to be returned in the response.
     * @param errorMessage A descriptive error message for the client.
     * @param request The {@link WebRequest} for context (used for logging path internally).
     * @return A {@link ResponseEntity} wrapping a {@link RestResponse} for the error.
     */
    private ResponseEntity<RestResponse<Object>> createErrorResponseEntity(HttpStatus status, String errorMessage, WebRequest request) {
        String requestPath = request.getDescription(false).replace("uri=", ""); // Extract URI for internal logging
        logger.debug("Creating error response entity. Status: {}, Message: {}, Request Path: {}", status.value(), errorMessage, requestPath);
        // The error message is now put into the 'data' map
        Map<String, String> errorData = new HashMap<>();
        errorData.put("error", errorMessage);
        return ResponseEntity.status(status).body(RestResponse.error(status.value(), errorData));
    }

    /**
     * Handles {@link UserNotFoundException} and returns a 404 Not Found response.
     * This exception is typically thrown when an operation is requested for a user that does not exist.
     *
     * @param ex The {@link UserNotFoundException} that was thrown.
     * @param request The {@link WebRequest} for context.
     * @return A {@link ResponseEntity} with {@code HttpStatus.NOT_FOUND} and an error message in the data payload.
     */
    @ExceptionHandler(UserNotFoundException.class)
    @ResponseBody
    public ResponseEntity<RestResponse<Object>> handleUserNotFound(UserNotFoundException ex, WebRequest request) {
        logger.warn("Caught UserNotFoundException: {} - Request Path: {}", ex.getMessage(), request.getDescription(false));
        return createErrorResponseEntity(HttpStatus.NOT_FOUND, ex.getMessage(), request);
    }

    /**
     * Handles {@link InvalidPasswordException} and returns a 401 Unauthorized response.
     * This exception is thrown when a password provided by the user does not match the stored password.
     *
     * @param ex The {@link InvalidPasswordException} that was thrown.
     * @param request The {@link WebRequest} for context.
     * @return A {@link ResponseEntity} with {@code HttpStatus.UNAUTHORIZED} and an error message in the data payload.
     */
    @ExceptionHandler(InvalidPasswordException.class)
    @ResponseBody
    public ResponseEntity<RestResponse<Object>> handleInvalidPassword(InvalidPasswordException ex, WebRequest request) {
        logger.warn("Caught InvalidPasswordException: {} - Request Path: {}", ex.getMessage(), request.getDescription(false));
        return createErrorResponseEntity(HttpStatus.UNAUTHORIZED, ex.getMessage(), request);
    }

    /**
     * Handles {@link ApiException} and returns a 400 Bad Request response.
     * This is a general-purpose exception for business logic errors that result in a bad request from the client.
     *
     * @param ex The {@link ApiException} that was thrown.
     * @param request The {@link WebRequest} for context.
     * @return A {@link ResponseEntity} with {@code HttpStatus.BAD_REQUEST} and an error message in the data payload.
     */
    @ExceptionHandler(ApiException.class)
    @ResponseBody
    public ResponseEntity<RestResponse<Object>> handleApiException(ApiException ex, WebRequest request) {
        logger.warn("Caught ApiException: {} - Request Path: {}", ex.getMessage(), request.getDescription(false));
        return createErrorResponseEntity(HttpStatus.BAD_REQUEST, ex.getMessage(), request);
    }

    /**
     * Handles {@link MethodArgumentNotValidException} which occurs when {@code @Valid} annotation
     * fails during DTO validation. It collects all validation errors and returns them in the data payload.
     *
     * @param ex The {@link MethodArgumentNotValidException} that was thrown.
     * @param request The {@link WebRequest} for context.
     * @return A {@link ResponseEntity} with {@code HttpStatus.BAD_REQUEST} and detailed validation error messages in the data payload.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseBody
    public ResponseEntity<RestResponse<Object>> handleValidationExceptions(MethodArgumentNotValidException ex, WebRequest request) {
        logger.warn("Caught MethodArgumentNotValidException: {} validation errors occurred for path: {}",
                ex.getBindingResult().getErrorCount(), request.getDescription(false));

        String detailedMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> {
                    String fieldName = ((FieldError) error).getField();
                    String errorMessage = error.getDefaultMessage();
                    logger.debug("Validation error: Field '{}' - Message: '{}'", fieldName, errorMessage);
                    return fieldName + ": " + errorMessage;
                })
                .collect(Collectors.joining("; "));

        return createErrorResponseEntity(HttpStatus.BAD_REQUEST, "Validation failed: " + detailedMessage, request);
    }

    /**
     * Catches any other uncaught {@link Exception} that might occur in the application.
     * This acts as a fallback to prevent internal server errors from exposing sensitive details to clients.
     *
     * @param ex The general {@link Exception} that was thrown.
     * @param request The {@link WebRequest} for context.
     * @return A {@link ResponseEntity} with {@code HttpStatus.INTERNAL_SERVER_ERROR} and a generic error message in the data payload.
     */
    @ExceptionHandler(Exception.class)
    @ResponseBody
    public ResponseEntity<RestResponse<Object>> handleGenericException(Exception ex, WebRequest request) {
        logger.error("Caught unhandled Exception: {} - Request Path: {}. Stack Trace: ",
                ex.getMessage(), request.getDescription(false), ex); // Log full stack trace for unhandled
        String errorMessage = "An unexpected error occurred. Please try again later.";
        return createErrorResponseEntity(HttpStatus.INTERNAL_SERVER_ERROR, errorMessage, request);
    }
}