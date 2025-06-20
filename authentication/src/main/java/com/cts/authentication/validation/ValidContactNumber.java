package com.cts.authentication.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = ContactNumberValidator.class)
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER, ElementType.ANNOTATION_TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidContactNumber {
    String message() default "Contact number must be 10 digits long and contain only numbers.";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}