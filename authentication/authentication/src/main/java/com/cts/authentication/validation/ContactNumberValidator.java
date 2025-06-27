package com.cts.authentication.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class ContactNumberValidator implements ConstraintValidator<ValidContactNumber, String> {

    @Override
    public void initialize(ValidContactNumber constraintAnnotation) {
        // No initialization needed
    }

    @Override
    public boolean isValid(String contactNumber, ConstraintValidatorContext context) {
        if (contactNumber == null || contactNumber.isEmpty()) {
            return false; // @NotBlank already handles null/empty
        }
        // Check if it's 10 digits and contains only numbers
        return contactNumber.matches("^\\d{10}$");
    }
}