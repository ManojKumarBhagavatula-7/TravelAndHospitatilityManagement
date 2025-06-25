package com.cts.authentication.controller;

import com.cts.authentication.dto.*;
import com.cts.authentication.exception.ApiException;
import com.cts.authentication.exception.InvalidPasswordException;
import com.cts.authentication.exception.UserNotFoundException;
import com.cts.authentication.response.RestResponse;
import com.cts.authentication.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthControllerTest {

    @InjectMocks
    private AuthController authController;

    @Mock
    private UserService userService;

    @Mock
    private HttpServletRequest httpServletRequest;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    // ========== LOGIN ==========
    @Test
    void login_shouldReturn200OnSuccess() {
        AuthRequest request = new AuthRequest("user@example.com", "password");
        Map<String, String> serviceResponse = Map.of(
            "message", "Login successful",
            "email", "user@example.com",
            "role", "USER",
            "token", "dummyToken"
        );

        when(userService.login(request)).thenReturn(serviceResponse);

        ResponseEntity<RestResponse<Object>> result = authController.login(request);

        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(200, result.getBody().getStatus());
        assertEquals(serviceResponse, result.getBody().getData());
        verify(userService).login(request);
    }

    @Test
    void login_shouldReturn401OnInvalidPassword() {
        AuthRequest request = new AuthRequest("user@example.com", "wrongPassword");
        InvalidPasswordException exception = new InvalidPasswordException("Invalid credentials");

        when(userService.login(request)).thenThrow(exception);

        ResponseEntity<RestResponse<Object>> result = authController.login(request);

        assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(401, result.getBody().getStatus());
        assertEquals(Map.of("error", exception.getMessage()), result.getBody().getData());
        verify(userService).login(request);
    }

    @Test
    void login_shouldReturn404WhenUserNotFound() {
        AuthRequest request = new AuthRequest("missing@example.com", "any");
        UserNotFoundException exception = new UserNotFoundException("User not found");

        when(userService.login(request)).thenThrow(exception);

        ResponseEntity<RestResponse<Object>> result = authController.login(request);

        assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(404, result.getBody().getStatus());
        assertEquals(Map.of("error", exception.getMessage()), result.getBody().getData());
        verify(userService).login(request);
    }

    @Test
    void login_shouldReturn500OnGenericException() {
        AuthRequest request = new AuthRequest("user@example.com", "password");
        RuntimeException exception = new RuntimeException("Database connection failed");

        when(userService.login(request)).thenThrow(exception);

        ResponseEntity<RestResponse<Object>> result = authController.login(request);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(500, result.getBody().getStatus());
        assertEquals(Map.of("error", "An unexpected error occurred during login."), result.getBody().getData());
        verify(userService).login(request);
    }

    // ========== REGISTER ==========
    @Test
    void register_shouldReturn201OnSuccess() {
        // Corrected RegisterRequest constructor based on previous conversation:
        // RegisterRequest(String name, String email, String password, String role, String contactNumber)
        RegisterRequest request = new RegisterRequest("Name", "newuser@example.com", "Password@123", "USER", "9876543210");
        Map<String, String> serviceResponse = Map.of("message", "User registered successfully.");

        when(userService.register(request)).thenReturn(serviceResponse);

        ResponseEntity<RestResponse<Object>> result = authController.register(request);

        assertEquals(HttpStatus.CREATED, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(201, result.getBody().getStatus());
        assertEquals(serviceResponse, result.getBody().getData());
        verify(userService).register(request);
    }

    @Test
    void register_shouldReturn409IfEmailExists() {
        RegisterRequest request = new RegisterRequest("Name", "exists@example.com", "Password@123", "USER", "9876543210");
        ApiException exception = new ApiException("User with this email already exists");

        when(userService.register(request)).thenThrow(exception);

        ResponseEntity<RestResponse<Object>> result = authController.register(request);

        assertEquals(HttpStatus.CONFLICT, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(409, result.getBody().getStatus());
        assertEquals(Map.of("error", exception.getMessage()), result.getBody().getData());
        verify(userService).register(request);
    }

    @Test
    void register_shouldReturn500OnGenericException() {
        RegisterRequest request = new RegisterRequest("Name", "error@example.com", "Password@123", "USER", "9876543210");
        RuntimeException exception = new RuntimeException("Some DB error");

        when(userService.register(request)).thenThrow(exception);

        ResponseEntity<RestResponse<Object>> result = authController.register(request);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(500, result.getBody().getStatus());
        assertEquals(Map.of("error", "An unexpected error occurred during registration."), result.getBody().getData());
        verify(userService).register(request);
    }

    // ========== FORGOT PASSWORD ==========
    @Test
    void forgotPassword_shouldReturn200OnSuccess() {
        ForgotPasswordRequest request = new ForgotPasswordRequest("user@example.com");
        Map<String, String> serviceResponse = Map.of("message", "Password reset link sent.", "resetToken", "abc123");

        when(userService.forgotPassword(request.getEmail())).thenReturn(serviceResponse);

        ResponseEntity<RestResponse<Object>> result = authController.forgotPassword(request);

        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(200, result.getBody().getStatus());
        assertEquals(serviceResponse, result.getBody().getData());
        verify(userService).forgotPassword(request.getEmail());
    }

    @Test
    void forgotPassword_shouldReturn404IfUserNotFound() {
        ForgotPasswordRequest request = new ForgotPasswordRequest("missing@example.com");
        UserNotFoundException exception = new UserNotFoundException("User not found");

        when(userService.forgotPassword(request.getEmail())).thenThrow(exception);

        ResponseEntity<RestResponse<Object>> result = authController.forgotPassword(request);

        assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(404, result.getBody().getStatus());
        assertEquals(Map.of("error", exception.getMessage()), result.getBody().getData());
        verify(userService).forgotPassword(request.getEmail());
    }

    @Test
    void forgotPassword_shouldReturn500OnGenericException() {
        ForgotPasswordRequest request = new ForgotPasswordRequest("user@example.com");
        RuntimeException exception = new RuntimeException("Mail server error");

        when(userService.forgotPassword(request.getEmail())).thenThrow(exception);

        ResponseEntity<RestResponse<Object>> result = authController.forgotPassword(request);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(500, result.getBody().getStatus());
        assertEquals(Map.of("error", "An unexpected error occurred during forgot password."), result.getBody().getData());
        verify(userService).forgotPassword(request.getEmail());
    }

    // ========== RESET PASSWORD ==========
    @Test
    void resetPassword_shouldReturn200OnSuccess() {
        ResetPasswordRequest request = new ResetPasswordRequest("token123", "NewPass@123", "NewPass@123");
        Map<String, String> serviceResponse = Map.of("message", "Password updated successfully.", "email", "user@example.com");

        when(userService.resetPassword("token123", "NewPass@123", "NewPass@123")).thenReturn(serviceResponse);

        ResponseEntity<RestResponse<Object>> result = authController.resetPassword(request);

        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(200, result.getBody().getStatus());
        assertEquals(serviceResponse, result.getBody().getData());
        verify(userService).resetPassword("token123", "NewPass@123", "NewPass@123");
    }

    @Test
    void resetPassword_shouldReturn400OnServiceApiException() {
        ResetPasswordRequest request = new ResetPasswordRequest("token123", "NewPass@123", "WrongPass");
        ApiException exception = new ApiException("Passwords do not match");

        when(userService.resetPassword(anyString(), anyString(), anyString())).thenThrow(exception);

        ResponseEntity<RestResponse<Object>> result = authController.resetPassword(request);

        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(400, result.getBody().getStatus());
        assertEquals(Map.of("error", exception.getMessage()), result.getBody().getData());
        verify(userService).resetPassword(request.getToken(), request.getNewPassword(), request.getConfirmPassword());
    }

    @Test
    void resetPassword_shouldReturn500OnGenericException() {
        ResetPasswordRequest request = new ResetPasswordRequest("token123", "NewPass@123", "NewPass@123");
        RuntimeException exception = new RuntimeException("Database error during reset");

        when(userService.resetPassword(anyString(), anyString(), anyString())).thenThrow(exception);

        ResponseEntity<RestResponse<Object>> result = authController.resetPassword(request);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(500, result.getBody().getStatus());
        assertEquals(Map.of("error", "An unexpected error occurred during password reset."), result.getBody().getData());
        verify(userService).resetPassword(request.getToken(), request.getNewPassword(), request.getConfirmPassword());
    }

    // ========== CHANGE PASSWORD ==========
    @Test
    void changePassword_shouldReturn200OnSuccess() {
        ChangePasswordRequest request = new ChangePasswordRequest("user@example.com", "OldPass@1", "NewPass@2", "NewPass@2");
        Map<String, String> serviceResponse = Map.of("message", "Password updated successfully.", "email", "user@example.com");

        when(userService.changePassword(anyString(), anyString(), anyString(), anyString())).thenReturn(serviceResponse);

        ResponseEntity<RestResponse<Object>> result = authController.changePassword(request);

        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(200, result.getBody().getStatus());
        assertEquals(serviceResponse, result.getBody().getData());
        verify(userService).changePassword(request.getEmail(), request.getCurrentPassword(), request.getNewPassword(), request.getConfirmPassword());
    }

    @Test
    void changePassword_shouldReturn401OnInvalidCurrentPassword() {
        ChangePasswordRequest request = new ChangePasswordRequest("user@example.com", "wrong", "new", "new");
        InvalidPasswordException exception = new InvalidPasswordException("Invalid current password");

        when(userService.changePassword(anyString(), anyString(), anyString(), anyString())).thenThrow(exception);

        ResponseEntity<RestResponse<Object>> result = authController.changePassword(request);

        assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(401, result.getBody().getStatus());
        assertEquals(Map.of("error", exception.getMessage()), result.getBody().getData());
        verify(userService).changePassword(request.getEmail(), request.getCurrentPassword(), request.getNewPassword(), request.getConfirmPassword());
    }

    @Test
    void changePassword_shouldReturn404IfUserNotFound() {
        ChangePasswordRequest request = new ChangePasswordRequest("missing@example.com", "old", "new", "new");
        UserNotFoundException exception = new UserNotFoundException("User not found");

        when(userService.changePassword(anyString(), anyString(), anyString(), anyString())).thenThrow(exception);

        ResponseEntity<RestResponse<Object>> result = authController.changePassword(request);

        assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(404, result.getBody().getStatus());
        assertEquals(Map.of("error", exception.getMessage()), result.getBody().getData());
        verify(userService).changePassword(request.getEmail(), request.getCurrentPassword(), request.getNewPassword(), request.getConfirmPassword());
    }

    @Test
    void changePassword_shouldReturn400OnServiceApiException() {
        ChangePasswordRequest request = new ChangePasswordRequest("user@example.com", "OldPass@1", "NewPass@2", "DifferentPass");
        ApiException exception = new ApiException("New passwords do not match");

        when(userService.changePassword(anyString(), anyString(), anyString(), anyString())).thenThrow(exception);

        ResponseEntity<RestResponse<Object>> result = authController.changePassword(request);

        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(400, result.getBody().getStatus());
        assertEquals(Map.of("error", exception.getMessage()), result.getBody().getData());
        verify(userService).changePassword(request.getEmail(), request.getCurrentPassword(), request.getNewPassword(), request.getConfirmPassword());
    }

    @Test
    void changePassword_shouldReturn500OnGenericException() {
        ChangePasswordRequest request = new ChangePasswordRequest("user@example.com", "OldPass@1", "NewPass@2", "NewPass@2");
        RuntimeException exception = new RuntimeException("Failed to update password in DB");

        when(userService.changePassword(anyString(), anyString(), anyString(), anyString())).thenThrow(exception);

        ResponseEntity<RestResponse<Object>> result = authController.changePassword(request);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(500, result.getBody().getStatus());
        assertEquals(Map.of("error", "An unexpected error occurred during password change."), result.getBody().getData());
        verify(userService).changePassword(request.getEmail(), request.getCurrentPassword(), request.getNewPassword(), request.getConfirmPassword());
    }

    // ========== LOGOUT ==========
    @Test
    void logout_shouldReturn200OnSuccess() {
        String token = "valid.jwt.token";
        when(httpServletRequest.getHeader("Authorization")).thenReturn("Bearer " + token);
        // Mocking behavior for void method, verify later
        doNothing().when(userService).logout(anyString());

        ResponseEntity<RestResponse<Object>> result = authController.logout(httpServletRequest);

        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(200, result.getBody().getStatus());
        assertEquals(Map.of("message", "Logged out successfully."), result.getBody().getData());
        verify(userService).logout(token);
    }

    @Test
    void logout_shouldReturn401IfAuthorizationHeaderMissing() {
        when(httpServletRequest.getHeader("Authorization")).thenReturn(null);

        ResponseEntity<RestResponse<Object>> result = authController.logout(httpServletRequest);

        assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(401, result.getBody().getStatus());
        assertEquals(Map.of("error", "Invalid or missing token"), result.getBody().getData());
        verify(userService, never()).logout(anyString()); // Ensure service method is NOT called
    }

    @Test
    void logout_shouldReturn401IfAuthorizationHeaderMalformed() {
        when(httpServletRequest.getHeader("Authorization")).thenReturn("InvalidTokenFormat"); // Missing "Bearer "

        ResponseEntity<RestResponse<Object>> result = authController.logout(httpServletRequest);

        assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(401, result.getBody().getStatus());
        assertEquals(Map.of("error", "Invalid or missing token"), result.getBody().getData());
        verify(userService, never()).logout(anyString()); // Ensure service method is NOT called
    }

    @Test
    void logout_shouldReturn500OnGenericException() {
        String token = "valid.jwt.token";
        when(httpServletRequest.getHeader("Authorization")).thenReturn("Bearer " + token);
        doThrow(new RuntimeException("Error during token invalidation")).when(userService).logout(anyString());

        ResponseEntity<RestResponse<Object>> result = authController.logout(httpServletRequest);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, result.getStatusCode());
        assertNotNull(result.getBody());
        assertEquals(500, result.getBody().getStatus());
        assertEquals(Map.of("error", "An unexpected error occurred during logout."), result.getBody().getData());
        verify(userService).logout(token);
    }
}