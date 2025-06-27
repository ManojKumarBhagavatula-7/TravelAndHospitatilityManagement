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
import com.cts.authentication.response.RestResponse; // Import the new RestResponse class

import jakarta.servlet.http.HttpServletRequest; // Keep if you need for logging, but not for RestResponse
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map; // Keep Map import as service still returns Map

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
     * Handles user login requests.
     * Authenticates the user with provided credentials and returns a JWT token upon successful login.
     *
     * @param request The authentication request containing user's email and password.
     * @return A {@link ResponseEntity} containing a {@link RestResponse} with login success details (including JWT token) or an error message.
     * <ul>
     * <li>{@code HttpStatus.OK} (200) with token and user info on success.</li>
     * <li>{@code HttpStatus.NOT_FOUND} (404) if user email is not found.</li>
     * <li>{@code HttpStatus.UNAUTHORIZED} (401) if credentials are invalid.</li>
     * <li>{@code HttpStatus.INTERNAL_SERVER_ERROR} (500) for unexpected errors.</li>
     * </ul>
     */
    @PostMapping("/login")
    public ResponseEntity<RestResponse<Object>> login(@Valid @RequestBody AuthRequest request) {
        logger.info("Received login request for email: {}", request.getEmail());
        logger.debug("AuthRequest details: Email={}", request.getEmail());

        try {
            Map<String, String> serviceResponseData = userService.login(request);
            logger.info("Login successful for email: {}", request.getEmail());
            return ResponseEntity.ok(
                RestResponse.success(HttpStatus.OK.value(), serviceResponseData)
            );
        } catch (UserNotFoundException e) {
            logger.warn("Login failed for email {}: User not found. Details: {}", request.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                RestResponse.error(HttpStatus.NOT_FOUND.value(), Map.of("error", e.getMessage()))
            );
        } catch (InvalidPasswordException e) {
            logger.warn("Login failed for email {}: Invalid credentials. Details: {}", request.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                RestResponse.error(HttpStatus.UNAUTHORIZED.value(), Map.of("error", e.getMessage()))
            );
        } catch (Exception e) {
            logger.error("An unexpected error occurred during login for email {}: {}", request.getEmail(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                RestResponse.error(HttpStatus.INTERNAL_SERVER_ERROR.value(), Map.of("error", "An unexpected error occurred during login."))
            );
        }
    }

    /**
     * Handles user registration requests.
     * Registers a new user with the provided details, including name, email, password, role, and contact number.
     *
     * @param request The registration request containing new user's details.
     * @return A {@link ResponseEntity} containing a {@link RestResponse} indicating successful registration or an error message.
     * <ul>
     * <li>{@code HttpStatus.CREATED} (201) on successful registration.</li>
     * <li>{@code HttpStatus.CONFLICT} (409) if a user with the provided email already exists.</li>
     * <li>{@code HttpStatus.BAD_REQUEST} (400) if validation fails (handled by GlobalExceptionHandler).</li>
     * <li>{@code HttpStatus.INTERNAL_SERVER_ERROR} (500) for unexpected errors.</li>
     * </ul>
     */
    @PostMapping("/register")
    public ResponseEntity<RestResponse<Object>> register(@Valid @RequestBody RegisterRequest request) {
        logger.info("Received registration request for email: {}", request.getEmail());
        logger.debug("RegisterRequest details: Name={}, Email={}, Role={}, ContactNumber={}",
                request.getName(), request.getEmail(), request.getRole(), request.getContactNumber());

        try {
            Map<String, String> serviceResponseData = userService.register(request);
            logger.info("Registration successful for email: {}", request.getEmail());
            return ResponseEntity.status(HttpStatus.CREATED).body(
                RestResponse.success(HttpStatus.CREATED.value(), serviceResponseData)
            );
        } catch (ApiException e) {
            logger.warn("Registration failed for email {}: Conflict - {}. Details: {}", request.getEmail(), e.getMessage(), e.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT).body( // 409 Conflict for existing user
                RestResponse.error(HttpStatus.CONFLICT.value(), Map.of("error", e.getMessage()))
            );
        } catch (Exception e) {
            logger.error("An unexpected error occurred during registration for email {}: {}", request.getEmail(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                RestResponse.error(HttpStatus.INTERNAL_SERVER_ERROR.value(), Map.of("error", "An unexpected error occurred during registration."))
            );
        }
    }

    /**
     * Initiates the "forgot password" process for a user.
     * This endpoint generates a reset token and, in a real application, would trigger an email containing this token.
     *
     * @param request The request containing the email for which to initiate password reset.
     * @return A {@link ResponseEntity} containing a {@link RestResponse} indicating that the password reset process has been initiated.
     * <ul>
     * <li>{@code HttpStatus.OK} (200) if the reset process is initiated successfully (token generated).</li>
     * <li>{@code HttpStatus.NOT_FOUND} (404) if no user is found with the provided email.</li>
     * <li>{@code HttpStatus.INTERNAL_SERVER_ERROR} (500) for unexpected errors.</li>
     * </ul>
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<RestResponse<Object>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        logger.info("Received forgot password request for email: {}", request.getEmail());
        logger.debug("ForgotPasswordRequest details: Email={}", request.getEmail());

        try {
            Map<String, String> serviceResponseData = userService.forgotPassword(request.getEmail());
            logger.info("Forgot password process initiated for email: {}", request.getEmail());
            return ResponseEntity.ok(
                RestResponse.success(HttpStatus.OK.value(), serviceResponseData)
            );
        } catch (UserNotFoundException e) {
            logger.warn("Forgot password failed for email {}: User not found. Details: {}", request.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                RestResponse.error(HttpStatus.NOT_FOUND.value(), Map.of("error", e.getMessage()))
            );
        } catch (Exception e) {
            logger.error("An unexpected error occurred during forgot password for email {}: {}", request.getEmail(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                RestResponse.error(HttpStatus.INTERNAL_SERVER_ERROR.value(), Map.of("error", "An unexpected error occurred during forgot password."))
            );
        }
    }

    /**
     * Handles the "reset password" functionality using a provided reset token.
     * The user provides a new password and its confirmation along with the token.
     *
     * @param request The request containing the reset token, new password, and confirmation password.
     * @return A {@link ResponseEntity} containing a {@link RestResponse} indicating successful password update or an error message.
     * <ul>
     * <li>{@code HttpStatus.OK} (200) on successful password reset.</li>
     * <li>{@code HttpStatus.BAD_REQUEST} (400) if passwords do not match or the token is invalid/expired.</li>
     * <li>{@code HttpStatus.INTERNAL_SERVER_ERROR} (500) for unexpected errors.</li>
     * </ul>
     */
    @PostMapping("/reset-password")
    public ResponseEntity<RestResponse<Object>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        logger.info("Received reset password request with token.");
        logger.debug("ResetPasswordRequest details: Token present? {}, New password length={}",
                request.getToken() != null && !request.getToken().isEmpty(), request.getNewPassword().length());

        try {
            Map<String, String> serviceResponseData = userService.resetPassword(
                request.getToken(),
                request.getNewPassword(),
                request.getConfirmPassword()
            );
            logger.info("Password reset successfully for user associated with token.");
            return ResponseEntity.ok(
                RestResponse.success(HttpStatus.OK.value(), serviceResponseData)
            );
        } catch (ApiException e) {
            logger.warn("Reset password failed: {}. Details: {}", e.getMessage(), e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                RestResponse.error(HttpStatus.BAD_REQUEST.value(), Map.of("error", e.getMessage()))
            );
        } catch (Exception e) {
            logger.error("An unexpected error occurred during reset password: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                RestResponse.error(HttpStatus.INTERNAL_SERVER_ERROR.value(), Map.of("error", "An unexpected error occurred during password reset."))
            );
        }
    }

    /**
     * Allows an authenticated user to change their password.
     * The user must provide their current password, along with the new password and its confirmation.
     *
     * @param request The request containing the user's email, current password, new password, and confirmation password.
     * @return A {@link ResponseEntity} containing a {@link RestResponse} indicating successful password change or an error message.
     * <ul>
     * <li>{@code HttpStatus.OK} (200) on successful password change.</li>
     * <li>{@code HttpStatus.NOT_FOUND} (404) if the user email is not found.</li>
     * <li>{@code HttpStatus.UNAUTHORIZED} (401) if the current password is incorrect.</li>
     * <li>{@code HttpStatus.BAD_REQUEST} (400) if new passwords do not match or validation fails.</li>
     * <li>{@code HttpStatus.INTERNAL_SERVER_ERROR} (500) for unexpected errors.</li>
     * </ul>
     */
    @PostMapping("/change-password")
    public ResponseEntity<RestResponse<Object>> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        logger.info("Received change password request for email: {}", request.getEmail());
        logger.debug("ChangePasswordRequest details: Email={}, New password length={}",
                request.getEmail(), request.getNewPassword().length());

        try {
            Map<String, String> serviceResponseData = userService.changePassword(
                request.getEmail(),
                request.getCurrentPassword(),
                request.getNewPassword(),
                request.getConfirmPassword()
            );
            logger.info("Password changed successfully for email: {}", request.getEmail());
            return ResponseEntity.ok(
                RestResponse.success(HttpStatus.OK.value(), serviceResponseData)
            );
        } catch (UserNotFoundException e) {
            logger.warn("Change password failed for email {}: User not found. Details: {}", request.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                RestResponse.error(HttpStatus.NOT_FOUND.value(), Map.of("error", e.getMessage()))
            );
        } catch (InvalidPasswordException e) {
            logger.warn("Change password failed for email {}: Invalid current password. Details: {}", request.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                RestResponse.error(HttpStatus.UNAUTHORIZED.value(), Map.of("error", e.getMessage()))
            );
        } catch (ApiException e) {
            logger.warn("Change password failed for email {}: Bad request. Details: {}", request.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                RestResponse.error(HttpStatus.BAD_REQUEST.value(), Map.of("error", e.getMessage()))
            );
        } catch (Exception e) {
            logger.error("An unexpected error occurred during change password for email {}: {}", request.getEmail(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                RestResponse.error(HttpStatus.INTERNAL_SERVER_ERROR.value(), Map.of("error", "An unexpected error occurred during password change."))
            );
        }
    }

    /**
     * Handles user logout by invalidating the provided JWT token.
     * The token is expected in the Authorization header as "Bearer [token]".
     * Once invalidated, the token cannot be used for further authentication.
     *
     * @param httpRequest The HttpServletRequest to extract the Authorization header.
     * @return A {@link ResponseEntity} containing a {@link RestResponse} indicating successful logout or an error message.
     * <ul>
     * <li>{@code HttpStatus.OK} (200) on successful logout.</li>
     * <li>{@code HttpStatus.UNAUTHORIZED} (401) if the Authorization header is missing or malformed.</li>
     * <li>{@code HttpStatus.INTERNAL_SERVER_ERROR} (500) for unexpected errors.</li>
     * </ul>
     */
    @PostMapping("/logout")
    public ResponseEntity<RestResponse<Object>> logout(HttpServletRequest httpRequest) {
        logger.info("Received logout request.");

        String authHeader = httpRequest.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            logger.warn("Logout failed: Invalid or missing Authorization header.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                RestResponse.error(HttpStatus.UNAUTHORIZED.value(), Map.of("error", "Invalid or missing token"))
            );
        }

        String token = authHeader.substring(7);
        logger.debug("Attempting to invalidate token: {}...", token.substring(0, Math.min(token.length(), 20)) + "..."); // Log partial token
        try {
            userService.logout(token);
            logger.info("User logged out successfully by invalidating token.");
            return ResponseEntity.ok(
                RestResponse.success(HttpStatus.OK.value(), Map.of("message", "Logged out successfully.")) // Provide message in data payload
            );
        } catch (Exception e) {
            logger.error("An unexpected error occurred during logout: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                RestResponse.error(HttpStatus.INTERNAL_SERVER_ERROR.value(), Map.of("error", "An unexpected error occurred during logout."))
            );
        }
    }
}