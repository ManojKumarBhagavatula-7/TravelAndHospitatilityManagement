package com.cts.authentication.controllertest;

import com.cts.authentication.CustomUserDetailsService;
import com.cts.authentication.JwtUtil;
import com.cts.authentication.controller.AuthController;
import com.cts.authentication.dto.AuthRequest;
import com.cts.authentication.dto.ChangePasswordRequest;
import com.cts.authentication.dto.ForgotPasswordRequest;
import com.cts.authentication.dto.RegisterRequest;
import com.cts.authentication.dto.ResetPasswordRequest;
import com.cts.authentication.exception.ApiException;
import com.cts.authentication.exception.InvalidPasswordException;
import com.cts.authentication.exception.UserNotFoundException;
import com.cts.authentication.service.JwtBlacklistService;
import com.cts.authentication.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean; 
import org.springframework.context.annotation.Primary; 
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity; 
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.SecurityFilterChain; 
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@DisplayName("Auth Controller Tests")
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private UserService userService;

    // Use @MockitoBean for security-related dependencies as well
    @MockitoBean
    private JwtUtil jwtUtil;

    @MockitoBean
    private CustomUserDetailsService customUserDetailsService;

    @MockitoBean
    private JwtBlacklistService jwtBlacklistService; // Assuming you have this service

    @Autowired
    private ObjectMapper objectMapper; // For converting DTOs to JSON

    // --- TEST SECURITY CONFIGURATION ---
    // This nested configuration will be picked up by @WebMvcTest
    // and will override or supplement your main security config for the test.
    @TestConfiguration
    static class TestSecurityConfig {

        @Bean
        @Primary // Ensures this bean is preferred over any other SecurityFilterChain bean
        public SecurityFilterChain testSecurityFilterChain(HttpSecurity http) throws Exception {
            http
                .csrf(AbstractHttpConfigurer::disable) // Disable CSRF for easier testing
                .authorizeHttpRequests(authorize -> authorize
                    .requestMatchers("/api/auth/**").permitAll() // Allow all auth endpoints
                    .anyRequest().authenticated() // All other requests require authentication
                )
                .exceptionHandling(exceptions -> exceptions
                    // Specifically configure authentication entry point to return 401 UNAUTHORIZED
                    // when an authentication attempt fails (e.g., bad credentials)
                    .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                );
            return http.build();
        }
    }
    // --- END TEST SECURITY CONFIGURATION ---


    // --- Login Tests ---
    @Test
    @DisplayName("Login: Should return 200 OK and token on successful login")
    void login_Success_ReturnsOk() throws Exception {
        AuthRequest request = new AuthRequest("test@example.com", "password");
        Map<String, String> serviceResponse = new HashMap<>();
        serviceResponse.put("message", "Login successful");
        serviceResponse.put("email", "test@example.com");
        serviceResponse.put("role", "TRAVELER");
        serviceResponse.put("token", "mockJwtToken");

        when(userService.login(any(AuthRequest.class))).thenReturn(serviceResponse);

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("200"))
                .andExpect(jsonPath("$.message").value("Login successful."))
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.token").value("mockJwtToken"));

        verify(userService).login(any(AuthRequest.class));
    }

    @Test
    @DisplayName("Login: Should return 404 NOT FOUND when user not found")
    void login_UserNotFound_ReturnsNotFound() throws Exception {
        AuthRequest request = new AuthRequest("nonexistent@example.com", "password");

        when(userService.login(any(AuthRequest.class))).thenThrow(new UserNotFoundException("User not found"));

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value("404"))
                .andExpect(jsonPath("$.error").value("Not Found"))
                .andExpect(jsonPath("$.message").value("User not found"));

        verify(userService).login(any(AuthRequest.class));
    }
    @Test
    @DisplayName("Login: Should return 401 UNAUTHORIZED on invalid password")
    void login_InvalidPassword_ReturnsUnauthorized() throws Exception {
        AuthRequest request = new AuthRequest("test@example.com", "wrongpassword");

        // When userService throws InvalidPasswordException
        when(userService.login(any(AuthRequest.class))).thenThrow(new InvalidPasswordException("Invalid credentials"));

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized()) // Now expects 401
                .andExpect(jsonPath("$.status").value("401"))
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.message").value("Invalid credentials"));

        verify(userService).login(any(AuthRequest.class));
    }

    @Test
    @DisplayName("Login: Should return 400 BAD REQUEST on invalid email format")
    void login_InvalidEmailFormat_ReturnsBadRequest() throws Exception {
        AuthRequest request = new AuthRequest("invalid-email", "password"); // Invalid email

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("Validation failed: email: Invalid email format"));

        verifyNoInteractions(userService); // Service should not be called due to validation error
    }

    // --- Register Tests ---
    @Test
    @DisplayName("Register: Should return 201 CREATED on successful registration")
    void register_Success_ReturnsCreated() throws Exception {
        RegisterRequest request = new RegisterRequest("New User", "new@example.com", "SecurePass123!", "TRAVELER", "1234567890");
        Map<String, String> serviceResponse = Map.of("message", "User registered successfully.");

        when(userService.register(any(RegisterRequest.class))).thenReturn(serviceResponse);

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("201"))
                .andExpect(jsonPath("$.message").value("User registered successfully."));

        verify(userService).register(any(RegisterRequest.class));
    }

    @Test
    @DisplayName("Register: Should return 409 CONFLICT if email already exists")
    void register_EmailAlreadyExists_ReturnsConflict() throws Exception {
        RegisterRequest request = new RegisterRequest("Existing User", "existing@example.com", "SecurePass123!", "TRAVELER", "1234567890");

        when(userService.register(any(RegisterRequest.class))).thenThrow(new ApiException("User with this email already exists"));

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value("409"))
                .andExpect(jsonPath("$.error").value("Conflict"))
                .andExpect(jsonPath("$.message").value("User with this email already exists"));

        verify(userService).register(any(RegisterRequest.class));
    }

    @Test
    @DisplayName("Register: Should return 400 BAD REQUEST on invalid password (due to @ValidPassword)")
    void register_InvalidPassword_ReturnsBadRequest() throws Exception {
        RegisterRequest request = new RegisterRequest("New User", "new@example.com", "weak", "TRAVELER", "1234567890"); // Weak password

        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.message").value("Validation failed: password: Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one digit, and one special character."));

        verifyNoInteractions(userService);
    }

    // --- Forgot Password Tests ---
    @Test
    @DisplayName("Forgot Password: Should return 200 OK on successful request")
    void forgotPassword_Success_ReturnsOk() throws Exception {
        ForgotPasswordRequest request = new ForgotPasswordRequest("test@example.com");
        Map<String, String> serviceResponse = Map.of("message", "Password reset link sent.", "resetToken", "dummyToken");

        when(userService.forgotPassword(anyString())).thenReturn(serviceResponse);

        mockMvc.perform(post("/api/auth/forgot-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("200"))
                .andExpect(jsonPath("$.message").value("Password reset link initiated."))
                .andExpect(jsonPath("$.resetToken").value("dummyToken"));

        verify(userService).forgotPassword(anyString());
    }

    @Test
    @DisplayName("Forgot Password: Should return 404 NOT FOUND if user not found")
    void forgotPassword_UserNotFound_ReturnsNotFound() throws Exception {
        ForgotPasswordRequest request = new ForgotPasswordRequest("nonexistent@example.com");

        when(userService.forgotPassword(anyString())).thenThrow(new UserNotFoundException("User not found"));

        mockMvc.perform(post("/api/auth/forgot-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value("404"))
                .andExpect(jsonPath("$.message").value("User not found"));

        verify(userService).forgotPassword(anyString());
    }

    // --- Reset Password Tests ---
    @Test
    @DisplayName("Reset Password: Should return 200 OK on successful reset")
    void resetPassword_Success_ReturnsOk() throws Exception {
        ResetPasswordRequest request = new ResetPasswordRequest("token123", "NewSecurePass1!", "NewSecurePass1!");
        Map<String, String> serviceResponse = Map.of("message", "Password updated successfully.", "email", "test@example.com");

        when(userService.resetPassword(anyString(), anyString(), anyString())).thenReturn(serviceResponse);

        mockMvc.perform(post("/api/auth/reset-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("200"))
                .andExpect(jsonPath("$.message").value("Password updated successfully."))
                .andExpect(jsonPath("$.email").value("test@example.com"));

        verify(userService).resetPassword(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("Reset Password: Should return 400 BAD REQUEST on password mismatch")
    void resetPassword_PasswordsMismatch_ReturnsBadRequest() throws Exception {
        ResetPasswordRequest request = new ResetPasswordRequest("token123", "NewSecurePass1!", "MismatchPass!");

        when(userService.resetPassword(anyString(), anyString(), anyString()))
                .thenThrow(new ApiException("Passwords do not match"));

        mockMvc.perform(post("/api/auth/reset-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.message").value("Passwords do not match"));

        verify(userService).resetPassword(anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("Reset Password: Should return 400 BAD REQUEST on invalid/expired token")
    void resetPassword_InvalidToken_ReturnsBadRequest() throws Exception {
        ResetPasswordRequest request = new ResetPasswordRequest("invalidToken", "NewSecurePass1!", "NewSecurePass1!");

        when(userService.resetPassword(anyString(), anyString(), anyString()))
                .thenThrow(new ApiException("Invalid or expired token"));

        mockMvc.perform(post("/api/auth/reset-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.message").value("Invalid or expired token"));

        verify(userService).resetPassword(anyString(), anyString(), anyString());
    }

    // --- Change Password Tests ---
    @Test
    @WithMockUser(username = "test@example.com") // Simulate an authenticated user
    @DisplayName("Change Password: Should return 200 OK on successful password change")
    void changePassword_Success_ReturnsOk() throws Exception {
        ChangePasswordRequest request = new ChangePasswordRequest("test@example.com", "CurrentPass1!", "NewPass2!", "NewPass2!");
        Map<String, String> serviceResponse = Map.of("message", "Password updated successfully.", "email", "test@example.com");

        when(userService.changePassword(anyString(), anyString(), anyString(), anyString())).thenReturn(serviceResponse);

        mockMvc.perform(post("/api/auth/change-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("200"))
                .andExpect(jsonPath("$.message").value("Password changed successfully."))
                .andExpect(jsonPath("$.email").value("test@example.com"));

        verify(userService).changePassword(anyString(), anyString(), anyString(), anyString());
    }

    @Test
    @WithMockUser(username = "test@example.com")
    @DisplayName("Change Password: Should return 404 NOT FOUND if user not found (though less likely with authentication)")
    void changePassword_UserNotFound_ReturnsNotFound() throws Exception {
        ChangePasswordRequest request = new ChangePasswordRequest("nonexistent@example.com", "CurrentPass1!", "NewPass2!", "NewPass2!");

        when(userService.changePassword(anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new UserNotFoundException("User not found"));

        mockMvc.perform(post("/api/auth/change-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value("404"))
                .andExpect(jsonPath("$.message").value("User not found"));

        verify(userService).changePassword(anyString(), anyString(), anyString(), anyString());
    }

    @Test
    @WithMockUser(username = "test@example.com")
    @DisplayName("Change Password: Should return 401 UNAUTHORIZED on incorrect current password")
    void changePassword_InvalidCurrentPassword_ReturnsUnauthorized() throws Exception {
        ChangePasswordRequest request = new ChangePasswordRequest("test@example.com", "WrongCurrentPass", "NewPass2!", "NewPass2!");

        when(userService.changePassword(anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new InvalidPasswordException("Current password is incorrect"));

        mockMvc.perform(post("/api/auth/change-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value("401"))
                .andExpect(jsonPath("$.message").value("Current password is incorrect"));

        verify(userService).changePassword(anyString(), anyString(), anyString(), anyString());
    }

    @Test
    @WithMockUser(username = "test@example.com")
    @DisplayName("Change Password: Should return 400 BAD REQUEST if new passwords do not match")
    void changePassword_NewPasswordsMismatch_ReturnsBadRequest() throws Exception {
        ChangePasswordRequest request = new ChangePasswordRequest("test@example.com", "CurrentPass1!", "NewPass2!", "MismatchPass");

        when(userService.changePassword(anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new ApiException("New passwords do not match"));

        mockMvc.perform(post("/api/auth/change-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.message").value("New passwords do not match"));

        verify(userService).changePassword(anyString(), anyString(), anyString(), anyString());
    }

    // --- Logout Tests ---
    @Test
    @WithMockUser(username = "test@example.com") // Simulate an authenticated user
    @DisplayName("Logout: Should return 200 OK on successful logout")
    void logout_Success_ReturnsOk() throws Exception {
        String token = "Bearer mockJwtToken";
        doNothing().when(userService).logout(anyString());

        mockMvc.perform(post("/api/auth/logout")
                .header("Authorization", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("200"))
                .andExpect(jsonPath("$.message").value("Logged out successfully."));

        verify(userService).logout("mockJwtToken"); // Verify with the extracted token
    }

    @Test
    @DisplayName("Logout: Should return 401 UNAUTHORIZED if Authorization header is missing")
    void logout_MissingAuthHeader_ReturnsUnauthorized() throws Exception {
        mockMvc.perform(post("/api/auth/logout"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value("401"))
                .andExpect(jsonPath("$.message").value("Invalid or missing token"));

        verifyNoInteractions(userService);
    }

    @Test
    @DisplayName("Logout: Should return 401 UNAUTHORIZED if Authorization header is malformed")
    void logout_MalformedAuthHeader_ReturnsUnauthorized() throws Exception {
        mockMvc.perform(post("/api/auth/logout")
                .header("Authorization", "InvalidToken"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value("401"))
                .andExpect(jsonPath("$.message").value("Invalid or missing token"));

        verifyNoInteractions(userService);
    }
}