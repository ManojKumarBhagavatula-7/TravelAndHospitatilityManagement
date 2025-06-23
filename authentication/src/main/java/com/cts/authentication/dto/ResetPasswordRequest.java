package com.cts.authentication.dto;
import com.cts.authentication.validation.ValidPassword;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResetPasswordRequest {
    @NotBlank(message = "Token is required")
    private String token;
    @NotBlank(message = "New password is required")
    @ValidPassword
    private String newPassword;
    @NotBlank(message = "Confirm password is required")
    private String confirmPassword;
}