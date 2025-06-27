package com.cts.authentication.service;

import com.cts.authentication.CustomUserDetails;
import com.cts.authentication.CustomUserDetailsService;
import com.cts.authentication.JwtUtil;
import com.cts.authentication.dto.AuthRequest;
import com.cts.authentication.dto.RegisterRequest;
import com.cts.authentication.entity.User;
import com.cts.authentication.exception.ApiException;
import com.cts.authentication.exception.InvalidPasswordException;
import com.cts.authentication.exception.UserNotFoundException;
import com.cts.authentication.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor; // Import for ArgumentCaptor
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime; // Added for User constructor
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

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
        // Initialize common test data
        // Ensure the User constructor matches your actual User entity's AllArgsConstructor
        // Assuming your User entity's @AllArgsConstructor looks like:
        // public User(Long userId, String name, String email, String password, String role, String contactNumber,
        //             String resetToken, LocalDateTime createdAt, LocalDateTime updatedAt, String createdBy, String updatedBy)
        testUser = new User(1L, "Test User", "test@example.com", "encodedCurrentPassword", "ROLE_USER", "1234567890", null, LocalDateTime.now(), LocalDateTime.now(), "system", "system");
        authRequest = new AuthRequest("test@example.com", "password123");
        registerRequest = new RegisterRequest("New User", "new@example.com", "SecurePassword1!", "ROLE_TRAVELER", "9876543210");
    }

    @Test
    @DisplayName("Login - Success")
    void login_Success() {
        // Specific stubbings for this test
        UserDetails mockUserDetails = new CustomUserDetails(testUser);
        when(userDetailsService.loadUserByUsername(anyString())).thenReturn(mockUserDetails);
        when(jwtUtil.generateToken(any(UserDetails.class))).thenReturn("mockJwtToken");

        when(userRepository.findByEmail(authRequest.getEmail())).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(authRequest.getPassword(), testUser.getPassword())).thenReturn(true);

        Map<String, String> response = userService.login(authRequest);

        assertNotNull(response);
        assertEquals("Login successful", response.get("message"));
        assertEquals(testUser.getEmail(), response.get("email"));
        assertEquals(testUser.getRole(), response.get("role"));
        assertEquals("mockJwtToken", response.get("token"));
        verify(userRepository, times(1)).findByEmail(authRequest.getEmail());
        verify(passwordEncoder, times(1)).matches(authRequest.getPassword(), testUser.getPassword());
        verify(userDetailsService, times(1)).loadUserByUsername(authRequest.getEmail());
        verify(jwtUtil, times(1)).generateToken(any(UserDetails.class));
    }

    @Test
    @DisplayName("Login - User Not Found")
    void login_UserNotFound() {
        when(userRepository.findByEmail(authRequest.getEmail())).thenReturn(Optional.empty());

        UserNotFoundException thrown = assertThrows(UserNotFoundException.class, () -> {
            userService.login(authRequest);
        });

        assertEquals("User not found", thrown.getMessage());
        verify(userRepository, times(1)).findByEmail(authRequest.getEmail());
        verify(passwordEncoder, never()).matches(anyString(), anyString());
        verify(userDetailsService, never()).loadUserByUsername(anyString());
        verify(jwtUtil, never()).generateToken(any(UserDetails.class));
    }

    @Test
    @DisplayName("Login - Invalid Password")
    void login_InvalidPassword() {
        when(userRepository.findByEmail(authRequest.getEmail())).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(authRequest.getPassword(), testUser.getPassword())).thenReturn(false);

        InvalidPasswordException thrown = assertThrows(InvalidPasswordException.class, () -> {
            userService.login(authRequest);
        });

        assertEquals("Invalid credentials", thrown.getMessage());
        verify(userRepository, times(1)).findByEmail(authRequest.getEmail());
        verify(passwordEncoder, times(1)).matches(authRequest.getPassword(), testUser.getPassword());
        verify(userDetailsService, never()).loadUserByUsername(anyString());
        verify(jwtUtil, never()).generateToken(any(UserDetails.class));
    }

    @Test
    @DisplayName("Register - Success")
    void register_Success() {
        when(userRepository.findByEmail(registerRequest.getEmail())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(registerRequest.getPassword())).thenReturn("encodedNewPassword");
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        Map<String, String> response = userService.register(registerRequest);

        assertNotNull(response);
        assertEquals("User registered successfully.", response.get("message"));
        verify(userRepository, times(1)).findByEmail(registerRequest.getEmail());
        verify(passwordEncoder, times(1)).encode(registerRequest.getPassword());
        verify(userRepository, times(1)).save(any(User.class));
        verify(userDetailsService, never()).loadUserByUsername(anyString());
        verify(jwtUtil, never()).generateToken(any(UserDetails.class));
    }

    @Test
    @DisplayName("Register - Email Already Exists")
    void register_EmailAlreadyExists() {
        when(userRepository.findByEmail(registerRequest.getEmail())).thenReturn(Optional.of(testUser));

        ApiException thrown = assertThrows(ApiException.class, () -> {
            userService.register(registerRequest);
        });

        assertEquals("User with this email already exists", thrown.getMessage());
        verify(userRepository, times(1)).findByEmail(registerRequest.getEmail());
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Forgot Password - Success")
    void forgotPassword_Success() {
        User userBeforeSave = new User(1L, "Test User", "test@example.com", "encodedPassword", "ROLE_USER", "1234567890", null, LocalDateTime.now(), LocalDateTime.now(), "system", "system");

        when(userRepository.findByEmail(userBeforeSave.getEmail())).thenReturn(Optional.of(userBeforeSave));

        // Use ArgumentCaptor to capture the User object passed to save
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        when(userRepository.save(userCaptor.capture())).thenReturn(userBeforeSave);

        Map<String, String> response = userService.forgotPassword(userBeforeSave.getEmail());

        assertNotNull(response);
        assertEquals("Password reset link sent.", response.get("message"));
        assertNotNull(response.get("resetToken"));

        verify(userRepository, times(1)).save(any(User.class)); // Verify save was called

        User capturedUser = userCaptor.getValue(); // Get the captured user object
        assertNotNull(capturedUser.getResetToken()); // Assert the captured user had a token
        assertEquals(response.get("resetToken"), capturedUser.getResetToken()); // Verify token consistency
    }


    @Test
    @DisplayName("Forgot Password - User Not Found")
    void forgotPassword_UserNotFound() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        UserNotFoundException thrown = assertThrows(UserNotFoundException.class, () -> {
            userService.forgotPassword("nonexistent@example.com");
        });

        assertEquals("User not found", thrown.getMessage());
        verify(userRepository, times(1)).findByEmail(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Reset Password - Success")
    void resetPassword_Success() {
        String resetToken = "validResetToken";
        User userWithToken = new User(1L, "Test User", "test@example.com", "oldPassword", "ROLE_USER", "1234567890", resetToken, LocalDateTime.now(), LocalDateTime.now(), "system", "system");

        when(userRepository.findByResetToken(resetToken)).thenReturn(Optional.of(userWithToken));
        when(passwordEncoder.encode("newPassword123!")).thenReturn("encodedNewPassword");
        when(userRepository.save(any(User.class))).thenReturn(userWithToken);

        Map<String, String> response = userService.resetPassword(resetToken, "newPassword123!", "newPassword123!");

        assertNotNull(response);
        assertEquals("Password updated successfully.", response.get("message"));
        assertEquals(userWithToken.getEmail(), response.get("email"));
        verify(userRepository, times(1)).findByResetToken(resetToken);
        verify(passwordEncoder, times(1)).encode("newPassword123!");
        verify(userRepository, times(1)).save(any(User.class));
        assertNull(userWithToken.getResetToken()); // Token should be null after reset
    }

    @Test
    @DisplayName("Reset Password - Passwords Mismatch")
    void resetPassword_PasswordsMismatch() {
        ApiException thrown = assertThrows(ApiException.class, () -> {
            userService.resetPassword("token", "newPassword123!", "differentPassword");
        });

        assertEquals("Passwords do not match", thrown.getMessage());
        verify(userRepository, never()).findByResetToken(anyString());
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Reset Password - Invalid or Expired Token")
    void resetPassword_InvalidOrExpiredToken() {
        when(userRepository.findByResetToken(anyString())).thenReturn(Optional.empty());

        ApiException thrown = assertThrows(ApiException.class, () -> {
            userService.resetPassword("invalidToken", "newPassword123!", "newPassword123!");
        });

        assertEquals("Invalid or expired token", thrown.getMessage());
        verify(userRepository, times(1)).findByResetToken("invalidToken");
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Change Password - Success")
    void changePassword_Success() {
        User user = new User(1L, "Test User", "test@example.com", "encodedCurrentPassword", "ROLE_USER", "1234567890", null, LocalDateTime.now(), LocalDateTime.now(), "system", "system");

        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("currentPassword", user.getPassword())).thenReturn(true);
        when(passwordEncoder.encode("newPassword123!")).thenReturn("encodedNewPassword");
        when(userRepository.save(any(User.class))).thenReturn(user);

        Map<String, String> response = userService.changePassword(user.getEmail(), "currentPassword", "newPassword123!", "newPassword123!");

        assertNotNull(response);
        assertEquals("Password updated successfully.", response.get("message"));
        assertEquals(user.getEmail(), response.get("email"));
        verify(userRepository, times(1)).findByEmail(user.getEmail());
        // FIX: Corrected the second argument in matches verification
        verify(passwordEncoder, times(1)).matches("currentPassword", "encodedCurrentPassword");
        verify(passwordEncoder, times(1)).encode("newPassword123!");
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    @DisplayName("Change Password - User Not Found")
    void changePassword_UserNotFound() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        UserNotFoundException thrown = assertThrows(UserNotFoundException.class, () -> {
            userService.changePassword("nonexistent@example.com", "current", "new", "new");
        });

        assertEquals("User not found", thrown.getMessage());
        verify(userRepository, times(1)).findByEmail(anyString());
        verify(passwordEncoder, never()).matches(anyString(), anyString());
    }

    @Test
    @DisplayName("Change Password - Incorrect Current Password")
    void changePassword_IncorrectCurrentPassword() {
        User user = new User(1L, "Test User", "test@example.com", "encodedCurrentPassword", "ROLE_USER", "1234567890", null, LocalDateTime.now(), LocalDateTime.now(), "system", "system");
        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrongCurrent", user.getPassword())).thenReturn(false);

        InvalidPasswordException thrown = assertThrows(InvalidPasswordException.class, () -> {
            userService.changePassword(user.getEmail(), "wrongCurrent", "newPassword123!", "newPassword123!");
        });

        assertEquals("Current password is incorrect", thrown.getMessage());
        verify(userRepository, times(1)).findByEmail(user.getEmail());
        verify(passwordEncoder, times(1)).matches("wrongCurrent", user.getPassword());
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    @DisplayName("Change Password - New Passwords Mismatch")
    void changePassword_NewPasswordsMismatch() {
        User user = new User(1L, "Test User", "test@example.com", "encodedCurrentPassword", "ROLE_USER", "1234567890", null, LocalDateTime.now(), LocalDateTime.now(), "system", "system");
        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("currentPassword", user.getPassword())).thenReturn(true);

        ApiException thrown = assertThrows(ApiException.class, () -> {
            userService.changePassword(user.getEmail(), "currentPassword", "newPassword123!", "differentNewPassword");
        });

        assertEquals("New passwords do not match", thrown.getMessage());
        verify(userRepository, times(1)).findByEmail(user.getEmail());
        verify(passwordEncoder, times(1)).matches("currentPassword", user.getPassword());
        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    @DisplayName("Logout - Success")
    void logout_Success() {
        // Specific stubbing for this test
        when(jwtUtil.extractUsername(anyString())).thenReturn("test@example.com");

        String token = "validJwtToken";
        doNothing().when(jwtBlacklistService).invalidateToken(token);

        userService.logout(token);

        verify(jwtUtil, times(1)).extractUsername(token);
        verify(jwtBlacklistService, times(1)).invalidateToken(token);
    }

    @Test
    @DisplayName("Logout - Token Extraction Fails (still blacklists)")
    void logout_TokenExtractionFails() {
        // Specific stubbing for this test
        when(jwtUtil.extractUsername(anyString())).thenThrow(new RuntimeException("Invalid JWT format"));

        String token = "invalidOrMalformedJwtToken";
        doNothing().when(jwtBlacklistService).invalidateToken(token);

        userService.logout(token);

        verify(jwtUtil, times(1)).extractUsername(token);
        verify(jwtBlacklistService, times(1)).invalidateToken(token);
    }
}
