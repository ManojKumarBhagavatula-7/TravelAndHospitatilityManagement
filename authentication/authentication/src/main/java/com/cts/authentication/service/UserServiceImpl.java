package com.cts.authentication.service;

import com.cts.authentication.JwtUtil;
import com.cts.authentication.CustomUserDetailsService;
import com.cts.authentication.dto.AuthRequest;
import com.cts.authentication.dto.RegisterRequest;
import com.cts.authentication.entity.User;
import com.cts.authentication.exception.ApiException;
import com.cts.authentication.exception.InvalidPasswordException;
import com.cts.authentication.exception.UserNotFoundException;
import com.cts.authentication.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Service implementation for user-related operations, including authentication, registration,
 * and password management.
 */
@Service
public class UserServiceImpl implements UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private JwtBlacklistService jwtBlacklistService;
    @Autowired
    private CustomUserDetailsService userDetailsService; // Used to load UserDetails for JWT

    /**
     * Authenticates a user based on their email and password.
     *
     * @param request The authentication request containing email and password.
     * @return A map containing a success message, user email, role, and a JWT token.
     * @throws UserNotFoundException If no user is found with the given email.
     * @throws InvalidPasswordException If the provided password does not match the stored password.
     */
    @Override
    public Map<String, String> login(AuthRequest request) {
        logger.info("Attempting login for email: {}", request.getEmail());

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> {
                    logger.warn("Login failed: User not found for email: {}", request.getEmail());
                    return new UserNotFoundException("User not found"); // Throw custom exception
                });

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            logger.error("Login failed: Invalid password for user: {}", request.getEmail());
            throw new InvalidPasswordException("Invalid credentials"); // Throw custom exception
        }

        // Load user details for JWT generation (already uses CustomUserDetails)
        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
        String token = jwtUtil.generateToken(userDetails);
        logger.debug("JWT token generated for user: {}", request.getEmail());

        Map<String, String> response = new HashMap<>();
        response.put("message", "Login successful");
        response.put("email", user.getEmail());
        response.put("role", user.getRole());
        response.put("token", token);

        logger.info("Login successful for user: {}", request.getEmail());
        return response;
    }

    /**
     * Registers a new user in the system.
     *
     * @param request The registration request containing user details.
     * @return A map containing a success message.
     * @throws ApiException If a user with the provided email already exists.
     */
    @Override
    public Map<String, String> register(RegisterRequest request) {
        logger.info("Attempting registration for email: {}", request.getEmail());

        // Check if a user with this email already exists
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            logger.warn("Registration failed: User with email {} already exists", request.getEmail());
            throw new ApiException("User with this email already exists"); // Use ApiException for a generic bad request type
        }

        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(request.getRole()); // Role validation happens via DTO @Pattern
        user.setContactNumber(request.getContactNumber());
        userRepository.save(user);

        logger.info("User registered successfully: {}", request.getEmail());
        return Map.of("message", "User registered successfully.");
    }

    /**
     * Initiates the forgot password process by generating a reset token for the given email.
     * In a real application, this token would be sent via email.
     *
     * @param email The email of the user requesting a password reset.
     * @return A map containing a success message and the generated reset token (for testing/debugging).
     * @throws UserNotFoundException If no user is found with the given email.
     */
    @Override
    public Map<String, String> forgotPassword(String email) {
        logger.info("Password reset requested for email: {}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.warn("Forgot password failed: User not found for email: {}", email);
                    return new UserNotFoundException("User not found");
                });

        String resetToken = UUID.randomUUID().toString();
        user.setResetToken(resetToken);
        userRepository.save(user);

        logger.info("Password reset token generated for email: {}", email);
        // TODO: In a real application, you would send this token via email/SMS here.
        // For example: emailService.sendPasswordResetEmail(user.getEmail(), resetToken);
        return Map.of("message", "Password reset link sent.", "resetToken", resetToken);
    }

    /**
     * Resets the user's password using a valid reset token.
     *
     * @param token The reset token received by the user.
     * @param newPassword The new password for the user.
     * @param confirmPassword The confirmation of the new password.
     * @return A map containing a success message and the user's email.
     * @throws ApiException If passwords do not match or the token is invalid/expired.
     */
    @Override
    public Map<String, String> resetPassword(String token, String newPassword, String confirmPassword) {
        logger.info("Attempting password reset with token.");

        if (!newPassword.equals(confirmPassword)) {
            logger.warn("Reset password failed: New passwords do not match for token.");
            throw new ApiException("Passwords do not match"); // Use ApiException
        }

        User user = userRepository.findByResetToken(token)
                .orElseThrow(() -> {
                    logger.warn("Reset password failed: Invalid or expired token.");
                    return new ApiException("Invalid or expired token"); // Use ApiException
                });

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetToken(null); // Invalidate the token after use
        userRepository.save(user);

        logger.info("Password updated successfully for user: {}", user.getEmail());
        return Map.of("message", "Password updated successfully.", "email", user.getEmail());
    }

    /**
     * Allows an authenticated user to change their password.
     *
     * @param email The email of the user changing the password.
     * @param currentPassword The user's current password.
     * @param newPassword The new password to set.
     * @param confirmPassword The confirmation of the new password.
     * @return A map containing a success message and the user's email.
     * @throws UserNotFoundException If the user is not found.
     * @throws InvalidPasswordException If the current password is incorrect.
     * @throws ApiException If the new passwords do not match.
     */
    @Override
    public Map<String, String> changePassword(String email, String currentPassword, String newPassword, String confirmPassword) {
        logger.info("Attempting password change for user: {}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.warn("Change password failed: User not found for email: {}", email);
                    return new UserNotFoundException("User not found");
                });

        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            logger.warn("Change password failed: Current password is incorrect for user: {}", email);
            throw new InvalidPasswordException("Current password is incorrect"); // Use InvalidPasswordException
        }

        if (!newPassword.equals(confirmPassword)) {
            logger.warn("Change password failed: New passwords do not match for user: {}", email);
            throw new ApiException("New passwords do not match"); // Use ApiException
        }
        
        // Optional: Add password strength validation here if not already done in DTO validation
        // if (!isValidPassword(newPassword)) {
        //     throw new ApiException("New password does not meet complexity requirements.");
        // }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        logger.info("Password updated successfully for user: {}", email);
        return Map.of("message", "Password updated successfully.", "email", user.getEmail());
    }

    /**
     * Invalidates a JWT token, effectively logging out the user associated with it.
     * The token is added to a blacklist to prevent its further use.
     *
     * @param token The JWT token to be blacklisted.
     */
    @Override
    public void logout(String token) {
        logger.info("Attempting to logout by invalidating token.");
        try {
            String username = jwtUtil.extractUsername(token);
            logger.debug("Invalidating token for user: {}", username);
        } catch (Exception e) {
            logger.warn("Could not extract username from token during logout for logging purposes: {}", e.getMessage());
        }
        jwtBlacklistService.invalidateToken(token);
        logger.info("Token blacklisted successfully.");
    }
}