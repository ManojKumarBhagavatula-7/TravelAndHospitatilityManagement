package com.cts.authentication.service;

import com.cts.authentication.dto.AuthRequest;
import com.cts.authentication.dto.RegisterRequest;
import java.util.Map;

/**
 * Interface for user-related operations, including authentication,
 * registration, password management, and logout.
 */
public interface UserService {
    /**
     * Authenticates a user with the provided credentials.
     *
     * @param request An {@link AuthRequest} containing the user's email and password.
     * @return A map containing a success message, user email, role, and a generated JWT token.
     */
    Map<String, String> login(AuthRequest request);

    /**
     * Registers a new user with the provided details.
     *
     * @param request A {@link RegisterRequest} containing the new user's details.
     * @return A map containing a success message.
     */
    Map<String, String> register(RegisterRequest request);

    /**
     * Initiates the forgot password process for a given email.
     * This typically involves generating a reset token and (in a real app) sending it to the user.
     *
     * @param email The email of the user who forgot their password.
     * @return A map containing a success message and the generated reset token (for demonstration).
     */
    Map<String, String> forgotPassword(String email);

    /**
     * Resets the user's password using a valid reset token.
     *
     * @param token The reset token received by the user.
     * @param newPassword The new password.
     * @param confirmPassword The confirmation of the new password.
     * @return A map containing a success message and the user's email.
     */
    Map<String, String> resetPassword(String token, String newPassword, String confirmPassword);

    /**
     * Allows a logged-in user to change their password.
     *
     * @param email The email of the user changing the password.
     * @param currentPassword The user's current password.
     * @param newPassword The new password.
     * @param confirmPassword The confirmation of the new password.
     * @return A map containing a success message and the user's email.
     */
    Map<String, String> changePassword(String email, String currentPassword, String newPassword, String confirmPassword);

    /**
     * Logs out a user by invalidating their JWT token.
     *
     * @param token The JWT token to be invalidated.
     */
    void logout(String token);
}