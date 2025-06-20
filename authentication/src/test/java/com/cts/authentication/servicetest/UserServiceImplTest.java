package com.cts.authentication.servicetest;

import com.cts.authentication.CustomUserDetailsService;
import com.cts.authentication.JwtUtil;
import com.cts.authentication.dto.AuthRequest;
import com.cts.authentication.dto.RegisterRequest;
import com.cts.authentication.entity.User;
import com.cts.authentication.exception.ApiException;
import com.cts.authentication.exception.InvalidPasswordException;
import com.cts.authentication.exception.UserNotFoundException;
import com.cts.authentication.repository.UserRepository;
import com.cts.authentication.service.JwtBlacklistService;
import com.cts.authentication.service.UserServiceImpl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("User Service Impl Tests")
public class UserServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private JwtBlacklistService jwtBlacklistService;

    @Mock
    private CustomUserDetailsService userDetailsService;

    @InjectMocks
    private UserServiceImpl userService;

    private User testUser;
    private AuthRequest authRequest;
    private RegisterRequest registerRequest;

    @BeforeEach
    void setUp() {
        testUser = new User(1L, "Test User", "test@example.com", "encodedPassword", "TRAVELER", "1234567890", null);

        authRequest = new AuthRequest("test@example.com", "rawPassword");

        registerRequest = new RegisterRequest(
                "New User",
                "newuser@example.com",
                "NewSecurePass1!",
                "TRAVELER",
                "9876543210"
        );
    }

    @Test
    @DisplayName("Login Success: Should return token and user details")
    void login_Success() {
        // Arrange
        when(userRepository.findByEmail(authRequest.getEmail())).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(authRequest.getPassword(), testUser.getPassword())).thenReturn(true);
        when(userDetailsService.loadUserByUsername(authRequest.getEmail())).thenReturn(mock(UserDetails.class));
        when(jwtUtil.generateToken(any(UserDetails.class))).thenReturn("mockJwtToken");

        // Act
        Map<String, String> response = userService.login(authRequest);

        // Assert
        assertThat(response).isNotNull();
        assertThat(response).containsEntry("message", "Login successful");
        assertThat(response).containsEntry("email", testUser.getEmail());
        assertThat(response).containsEntry("role", testUser.getRole());
        assertThat(response).containsEntry("token", "mockJwtToken");

        verify(userRepository).findByEmail(authRequest.getEmail());
        verify(passwordEncoder).matches(authRequest.getPassword(), testUser.getPassword());
        verify(userDetailsService).loadUserByUsername(authRequest.getEmail());
        verify(jwtUtil).generateToken(any(UserDetails.class));
    }

    @Test
    @DisplayName("Login Failure: User not found")
    void login_UserNotFound_ThrowsUserNotFoundException() {
        // Arrange
        when(userRepository.findByEmail(authRequest.getEmail())).thenReturn(Optional.empty());

        // Act & Assert
        UserNotFoundException exception = assertThrows(UserNotFoundException.class, () -> userService.login(authRequest));
        assertThat(exception.getMessage()).isEqualTo("User not found");

        verify(userRepository).findByEmail(authRequest.getEmail());
        verifyNoMoreInteractions(passwordEncoder, jwtUtil, userDetailsService); // Ensure no further calls
    }

    @Test
    @DisplayName("Login Failure: Invalid password")
    void login_InvalidPassword_ThrowsInvalidPasswordException() {
        // Arrange
        when(userRepository.findByEmail(authRequest.getEmail())).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(authRequest.getPassword(), testUser.getPassword())).thenReturn(false);

        // Act & Assert
        InvalidPasswordException exception = assertThrows(InvalidPasswordException.class, () -> userService.login(authRequest));
        assertThat(exception.getMessage()).isEqualTo("Invalid credentials");

        verify(userRepository).findByEmail(authRequest.getEmail());
        verify(passwordEncoder).matches(authRequest.getPassword(), testUser.getPassword());
        verifyNoMoreInteractions(jwtUtil, userDetailsService);
    }

    @Test
    @DisplayName("Register Success: Should save new user and return success message")
    void register_Success() {
        // Arrange
        when(userRepository.findByEmail(registerRequest.getEmail())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(registerRequest.getPassword())).thenReturn("encodedNewPassword");
        when(userRepository.save(any(User.class))).thenReturn(new User()); // Simulate save

        // Act
        Map<String, String> response = userService.register(registerRequest);

        // Assert
        assertThat(response).isNotNull();
        assertThat(response).containsEntry("message", "User registered successfully.");

        verify(userRepository).findByEmail(registerRequest.getEmail());
        verify(passwordEncoder).encode(registerRequest.getPassword());
        verify(userRepository).save(any(User.class)); // Verify a User object was saved
    }

    @Test
    @DisplayName("Register Failure: User with email already exists")
    void register_EmailAlreadyExists_ThrowsApiException() {
        // Arrange
        when(userRepository.findByEmail(registerRequest.getEmail())).thenReturn(Optional.of(new User()));

        // Act & Assert
        ApiException exception = assertThrows(ApiException.class, () -> userService.register(registerRequest));
        assertThat(exception.getMessage()).isEqualTo("User with this email already exists");

        verify(userRepository).findByEmail(registerRequest.getEmail());
        verifyNoMoreInteractions(passwordEncoder, userRepository); // No encoding or saving should happen
    }

    @Test
    @DisplayName("Forgot Password Success: Should generate and return reset token")
    void forgotPassword_Success() {
        // Arrange
        when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // Act
        Map<String, String> response = userService.forgotPassword(testUser.getEmail());

        // Assert
        assertThat(response).isNotNull();
        assertThat(response).containsEntry("message", "Password reset link sent.");
        assertThat(response).containsKey("resetToken"); // Check for presence, not specific value as it's UUID

        verify(userRepository).findByEmail(testUser.getEmail());
        verify(userRepository).save(any(User.class)); // Verify user with token was saved
    }

    @Test
    @DisplayName("Forgot Password Failure: User not found")
    void forgotPassword_UserNotFound_ThrowsUserNotFoundException() {
        // Arrange
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        // Act & Assert
        UserNotFoundException exception = assertThrows(UserNotFoundException.class, () -> userService.forgotPassword("nonexistent@example.com"));
        assertThat(exception.getMessage()).isEqualTo("User not found");

        verify(userRepository).findByEmail(anyString());
        verifyNoMoreInteractions(userRepository); // No saving should occur
    }

    @Test
    @DisplayName("Reset Password Success: Should update password and clear token")
    void resetPassword_Success() {
        // Arrange
        String token = "validResetToken";
        String newPassword = "NewStrongPassword1!";
        String confirmPassword = "NewStrongPassword1!";
        testUser.setResetToken(token); // Set the token on the test user

        when(userRepository.findByResetToken(token)).thenReturn(Optional.of(testUser));
        when(passwordEncoder.encode(newPassword)).thenReturn("encodedNewPassword");
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // Act
        Map<String, String> response = userService.resetPassword(token, newPassword, confirmPassword);

        // Assert
        assertThat(response).isNotNull();
        assertThat(response).containsEntry("message", "Password updated successfully.");
        assertThat(response).containsEntry("email", testUser.getEmail());
        assertThat(testUser.getResetToken()).isNull(); // Verify token is cleared

        verify(userRepository).findByResetToken(token);
        verify(passwordEncoder).encode(newPassword);
        verify(userRepository).save(any(User.class));
    }

    @Test
    @DisplayName("Reset Password Failure: Passwords do not match")
    void resetPassword_PasswordsMismatch_ThrowsApiException() {
        // Act & Assert
        ApiException exception = assertThrows(ApiException.class, () ->
                userService.resetPassword("token", "newPass", "mismatchPass"));
        assertThat(exception.getMessage()).isEqualTo("Passwords do not match");

        verifyNoInteractions(userRepository, passwordEncoder); // Nothing should be called
    }

    @Test
    @DisplayName("Reset Password Failure: Invalid or expired token")
    void resetPassword_InvalidToken_ThrowsApiException() {
        // Arrange
        when(userRepository.findByResetToken(anyString())).thenReturn(Optional.empty());

        // Act & Assert
        ApiException exception = assertThrows(ApiException.class, () ->
                userService.resetPassword("invalidToken", "newPass", "newPass"));
        assertThat(exception.getMessage()).isEqualTo("Invalid or expired token");

        verify(userRepository).findByResetToken(anyString());
        verifyNoMoreInteractions(userRepository, passwordEncoder);
    }

    @Test
    @DisplayName("Change Password Success: Should update password")
    void changePassword_Success() {
        // Arrange
        String currentPassword = "rawPassword";
        String newPassword = "NewSecurePassword2!";
        String confirmPassword = "NewSecurePassword2!";

        // testUser already has encodedPassword as its current password
        when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(currentPassword, "encodedPassword")).thenReturn(true);
        when(passwordEncoder.encode(newPassword)).thenReturn("encodedNewPassword");
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // Act
        Map<String, String> response = userService.changePassword(testUser.getEmail(), currentPassword, newPassword, confirmPassword);

        // Assert
        assertThat(response).isNotNull();
        assertThat(response).containsEntry("message", "Password updated successfully.");
        assertThat(response).containsEntry("email", testUser.getEmail());

        verify(userRepository).findByEmail(testUser.getEmail());
        verify(passwordEncoder).matches(currentPassword, "encodedPassword"); // ✅ FIXED LINE
        verify(passwordEncoder).encode(newPassword);
        verify(userRepository).save(any(User.class));
    }
    @Test
    @DisplayName("Change Password Failure: User not found")
    void changePassword_UserNotFound_ThrowsUserNotFoundException() {
        // Arrange
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        // Act & Assert
        UserNotFoundException exception = assertThrows(UserNotFoundException.class, () ->
                userService.changePassword("nonexistent@example.com", "old", "new", "new"));
        assertThat(exception.getMessage()).isEqualTo("User not found");

        verify(userRepository).findByEmail(anyString());
        verifyNoMoreInteractions(passwordEncoder, userRepository);
    }

    @Test
    @DisplayName("Change Password Failure: Current password incorrect")
    void changePassword_InvalidCurrentPassword_ThrowsInvalidPasswordException() {
        // Arrange
        when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(anyString(), eq("encodedPassword"))).thenReturn(false); // ✅ FIXED LINE

        // Act & Assert
        InvalidPasswordException exception = assertThrows(InvalidPasswordException.class, () ->
                userService.changePassword(testUser.getEmail(), "wrongPassword", "new", "new"));
        assertThat(exception.getMessage()).isEqualTo("Current password is incorrect");

        verify(userRepository).findByEmail(testUser.getEmail());
        verify(passwordEncoder).matches(anyString(), eq("encodedPassword")); // ✅ FIXED VERIFICATION TOO
        verifyNoMoreInteractions(passwordEncoder, userRepository);
    }

    @Test
    @DisplayName("Change Password Failure: New passwords do not match")
    void changePassword_NewPasswordsMismatch_ThrowsApiException() {
        // Arrange
        when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(anyString(), eq("encodedPassword"))).thenReturn(true); // ✅ FIXED LINE

        // Act & Assert
        ApiException exception = assertThrows(ApiException.class, () ->
                userService.changePassword(testUser.getEmail(), "rawPassword", "newPass", "mismatchPass"));

        assertThat(exception.getMessage()).isEqualTo("New passwords do not match");

        verify(userRepository).findByEmail(testUser.getEmail());
        verify(passwordEncoder).matches(anyString(), eq("encodedPassword")); // ✅ FIXED VERIFICATION
        verifyNoMoreInteractions(passwordEncoder, userRepository);
    }

    @Test
    @DisplayName("Logout Success: Should invalidate token")
    void logout_Success() {
        // Arrange
        String token = "validJwtToken";
        when(jwtUtil.extractUsername(token)).thenReturn("test@example.com");
        doNothing().when(jwtBlacklistService).invalidateToken(token);

        // Act
        userService.logout(token);

        // Assert
        verify(jwtBlacklistService).invalidateToken(token);
        verify(jwtUtil).extractUsername(token);
    }

    @Test
    @DisplayName("Logout Handles Token Extraction Exception Gracefully")
    void logout_TokenExtractionFails_StillInvalidates() {
        // Arrange
        String token = "invalidJwtToken";
        when(jwtUtil.extractUsername(token)).thenThrow(new RuntimeException("Bad token format"));
        doNothing().when(jwtBlacklistService).invalidateToken(token);

        // Act
        userService.logout(token);

        // Assert
        verify(jwtBlacklistService).invalidateToken(token); // Still invalidates even if username extraction fails
        verify(jwtUtil).extractUsername(token);
    }
}