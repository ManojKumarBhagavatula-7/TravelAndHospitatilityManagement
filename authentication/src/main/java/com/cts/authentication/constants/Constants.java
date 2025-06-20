package com.cts.authentication.constants;

/**
 * Centralized class for application-wide string constants.
 * This helps in avoiding magic strings and promotes code reusability and maintainability.
 */
public final class Constants {

    // Prevent instantiation of this utility class
    private Constants() {
        // Private constructor to prevent instantiation
    }

    // --- Log Messages ---
    public static final String LOGIN_FAILED_WARN_MSG = "Login failed for email {}: {}";
    public static final String REGISTRATION_FAILED_WARN_MSG = "Registration failed for email {}: {}";
    public static final String FORGOT_PASSWORD_FAILED_WARN_MSG = "Forgot password failed for email {}: {}";
    public static final String RESET_PASSWORD_FAILED_WARN_MSG = "Reset password failed: {}";
    public static final String CHANGE_PASSWORD_FAILED_WARN_MSG = "Change password failed for email {}: {}";

    // --- Error Messages for Responses ---
    public static final String UNEXPECTED_ERROR_LOGIN = "An unexpected error occurred during login.";
    public static final String UNEXPECTED_ERROR_REGISTRATION = "An unexpected error occurred during registration.";
    public static final String UNEXPECTED_ERROR_FORGOT_PASSWORD = "An unexpected error occurred during forgot password.";
    public static final String UNEXPECTED_ERROR_RESET_PASSWORD = "An unexpected error occurred during password reset.";
    public static final String UNEXPECTED_ERROR_CHANGE_PASSWORD = "An unexpected error occurred during password change.";
    public static final String UNEXPECTED_ERROR_LOGOUT = "An unexpected error occurred during logout.";
    public static final String LOGOUT_INVALID_TOKEN = "Invalid or missing token";

    // --- Success Messages for Responses ---
    public static final String LOGIN_SUCCESS_MSG = "Login successful.";
    public static final String REGISTRATION_SUCCESS_MSG = "User registered successfully.";
    public static final String PASSWORD_RESET_INITIATED_MSG = "Password reset link initiated.";
    public static final String PASSWORD_UPDATED_SUCCESS_MSG = "Password updated successfully.";
    public static final String PASSWORD_CHANGED_SUCCESS_MSG = "Password changed successfully.";
    public static final String LOGOUT_SUCCESS_MSG = "Logged out successfully.";

    // --- Other Constants ---
    public static final String BEARER_TOKEN_PREFIX = "Bearer ";
    public static final int BEARER_TOKEN_PREFIX_LENGTH = 7; // Length of "Bearer "

}