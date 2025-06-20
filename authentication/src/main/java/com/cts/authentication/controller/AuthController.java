package com.cts.authentication.controller;

import com.cts.authentication.dto.AuthRequest;
import com.cts.authentication.dto.ChangePasswordRequest;
import com.cts.authentication.dto.ForgotPasswordRequest;
import com.cts.authentication.dto.RegisterRequest;
import com.cts.authentication.dto.ResetPasswordRequest;
import com.cts.authentication.service.UserService;
import com.cts.authentication.exception.ApiException;
import com.cts.authentication.exception.InvalidPasswordException;
import com.cts.authentication.exception.UserNotFoundException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * REST controller for handling authentication-related requests.
 * Provides endpoints for user login, registration, password management (forgot, reset, change), and logout.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private UserService userService;

    /**
     * Helper method to create a consistent error response.
     *
     * @param status The HTTP status to return.
     * @param message A descriptive error message.
     * @return A {@link ResponseEntity} containing a map with error details.
     */
    private ResponseEntity<Map<String, String>> createErrorResponse(HttpStatus status, String message) {
        logger.debug("Creating error response with status {} and message: {}", status, message);
        return ResponseEntity.status(status).body(Map.of("status", String.valueOf(status.value()), "error", status.getReasonPhrase(), "message", message));
    }

    /**
     * Helper method to create a consistent success response.
     *
     * @param status The HTTP status to return.
     * @param message A descriptive success message.
     * @param data A map containing additional data to include in the response body.
     * @return A {@link ResponseEntity} containing a map with success details and provided data.
     */
    private ResponseEntity<Map<String, String>> createSuccessResponse(HttpStatus status, String message, Map<String, String> data) {
        logger.debug("Creating success response with status {} and message: {}", status, message);
        Map<String, String> response = new HashMap<>(data); // Start with data from service
        response.put("status", String.valueOf(status.value())); // Add numeric status code
        response.put("message", message); // Add a general success message
        response.put("code", status.getReasonPhrase()); // Add the reason phrase (e.g., "OK", "Created")
        return ResponseEntity.status(status).body(response);
    }

    /**
     * Handles user login requests.
     *
     * @param request The authentication request containing user credentials (email and password).
     * @return A {@link ResponseEntity} with login success details (e.g., JWT token) or an error message.
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@Valid @RequestBody AuthRequest request) {
        logger.info("Received login request for email: {}", request.getEmail());
        try {
            Map<String, String> serviceResponse = userService.login(request);
            logger.info("Login successful for email: {}", request.getEmail());
            return createSuccessResponse(HttpStatus.OK, "Login successful.", serviceResponse);
        } catch (UserNotFoundException e) {
            logger.warn("Login failed for email {}: {}", request.getEmail(), e.getMessage());
            return createErrorResponse(HttpStatus.NOT_FOUND, e.getMessage());
        } catch (InvalidPasswordException e) {
            logger.warn("Login failed for email {}: {}", request.getEmail(), e.getMessage());
            return createErrorResponse(HttpStatus.UNAUTHORIZED, e.getMessage());
        } catch (Exception e) {
            logger.error("An unexpected error occurred during login for email {}: {}", request.getEmail(), e.getMessage(), e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred during login.");
        }
    }

    /**
     * Handles user registration requests.
     *
     * @param request The registration request containing user details (name, email, password, role, contact number).
     * @return A {@link ResponseEntity} indicating successful registration or an error message if the user already exists.
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@Valid @RequestBody RegisterRequest request) {
        logger.info("Received registration request for email: {}", request.getEmail());
        try {
            Map<String, String> serviceResponse = userService.register(request);
            logger.info("Registration successful for email: {}", request.getEmail());
            return createSuccessResponse(HttpStatus.CREATED, "User registered successfully.", serviceResponse);
        } catch (ApiException e) {
            logger.warn("Registration failed for email {}: {}", request.getEmail(), e.getMessage());
            return createErrorResponse(HttpStatus.CONFLICT, e.getMessage()); // 409 Conflict for existing user
        } catch (Exception e) {
            logger.error("An unexpected error occurred during registration for email {}: {}", request.getEmail(), e.getMessage(), e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred during registration.");
        }
    }

    /**
     * Initiates the "forgot password" process.
     *
     * @param request The request containing the email for which to initiate password reset.
     * @return A {@link ResponseEntity} indicating that the password reset link has been initiated.
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        logger.info("Received forgot password request for email: {}", request.getEmail());
        try {
            Map<String, String> serviceResponse = userService.forgotPassword(request.getEmail());
            logger.info("Forgot password process initiated for email: {}", request.getEmail());
            return createSuccessResponse(HttpStatus.OK, "Password reset link initiated.", serviceResponse);
        } catch (UserNotFoundException e) {
            logger.warn("Forgot password failed for email {}: {}", request.getEmail(), e.getMessage());
            return createErrorResponse(HttpStatus.NOT_FOUND, e.getMessage());
        } catch (Exception e) {
            logger.error("An unexpected error occurred during forgot password for email {}: {}", request.getEmail(), e.getMessage(), e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred during forgot password.");
        }
    }

    /**
     * Handles the "reset password" functionality using a provided token.
     *
     * @param request The request containing the reset token, new password, and confirmation password.
     * @return A {@link ResponseEntity} indicating successful password update or an error message.
     */
    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        logger.info("Received reset password request with token.");
        try {
            Map<String, String> serviceResponse = userService.resetPassword(
                request.getToken(),
                request.getNewPassword(),
                request.getConfirmPassword()
            );
            logger.info("Password reset successfully.");
            return createSuccessResponse(HttpStatus.OK, "Password updated successfully.", serviceResponse);
        } catch (ApiException e) {
            logger.warn("Reset password failed: {}", e.getMessage());
            return createErrorResponse(HttpStatus.BAD_REQUEST, e.getMessage());
        } catch (Exception e) {
            logger.error("An unexpected error occurred during reset password: {}", e.getMessage(), e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred during password reset.");
        }
    }

    /**
     * Allows an authenticated user to change their password.
     *
     * @param request The request containing the user's email, current password, new password, and confirmation password.
     * @return A {@link ResponseEntity} indicating successful password change or an error message.
     */
    @PostMapping("/change-password")
    public ResponseEntity<Map<String, String>> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        logger.info("Received change password request for email: {}", request.getEmail());
        try {
            Map<String, String> serviceResponse = userService.changePassword(
                request.getEmail(),
                request.getCurrentPassword(),
                request.getNewPassword(),
                request.getConfirmPassword()
            );
            logger.info("Password changed successfully for email: {}", request.getEmail());
            return createSuccessResponse(HttpStatus.OK, "Password changed successfully.", serviceResponse);
        } catch (UserNotFoundException e) {
            logger.warn("Change password failed for email {}: {}", request.getEmail(), e.getMessage());
            return createErrorResponse(HttpStatus.NOT_FOUND, e.getMessage());
        } catch (InvalidPasswordException e) {
            logger.warn("Change password failed for email {}: {}", request.getEmail(), e.getMessage());
            return createErrorResponse(HttpStatus.UNAUTHORIZED, e.getMessage());
        } catch (ApiException e) {
            logger.warn("Change password failed for email {}: {}", request.getEmail(), e.getMessage());
            return createErrorResponse(HttpStatus.BAD_REQUEST, e.getMessage());
        } catch (Exception e) {
            logger.error("An unexpected error occurred during change password for email {}: {}", request.getEmail(), e.getMessage(), e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred during password change.");
        }
    }

    /**
     * Handles user logout by invalidating the provided JWT token.
     * Expects the JWT token in the Authorization header as "Bearer [token]".
     *
     * @param request The HttpServletRequest to extract the Authorization header.
     * @return A {@link ResponseEntity} indicating successful logout or an error message.
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request) {
        logger.info("Received logout request.");
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            logger.warn("Logout failed: Invalid or missing Authorization header.");
            return createErrorResponse(HttpStatus.UNAUTHORIZED, "Invalid or missing token");
        }
        String token = authHeader.substring(7);
        try {
            userService.logout(token);
            logger.info("User logged out successfully by invalidating token.");
            // For logout, the service returns void, so create a success response directly.
            return createSuccessResponse(HttpStatus.OK, "Logged out successfully.", new HashMap<>());
        } catch (Exception e) {
            logger.error("An unexpected error occurred during logout: {}", e.getMessage(), e);
            return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred during logout.");
        }
    }
}