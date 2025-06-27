package com.cts.authentication.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PasswordConstraintValidator implements ConstraintValidator<ValidPassword, String> {

    // Regex for strong password:
    // At least 8 characters
    // At least one uppercase letter (A-Z)
    // At least one lowercase letter (a-z)
    // At least one digit (0-9)
    // At least one special character (e.g., !@#$%^&*)
    private static final String PASSWORD_PATTERN = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+={}\\[\\]|:;\"'<>,.?/~`]).{8,}$";
    private static final Pattern pattern = Pattern.compile(PASSWORD_PATTERN);

    @Override
    public void initialize(ValidPassword constraintAnnotation) {
        // No initialization needed
    }

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null || password.isEmpty()) {
            return false; // @NotBlank already handles null/empty, but good to double-check
        }
        Matcher matcher = pattern.matcher(password);
        return matcher.matches();
    }
}