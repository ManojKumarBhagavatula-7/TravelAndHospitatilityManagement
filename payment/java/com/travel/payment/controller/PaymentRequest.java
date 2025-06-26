package com.travel.payment.controller;

import java.math.BigDecimal;
import java.time.LocalDateTime;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PaymentRequest {

    @NotNull(message = "User ID is required")
    private Integer userId;

    @NotNull(message = "Booking ID is required")
    private Integer bookingId;

    @NotNull(message = "Amount is required")
    private BigDecimal amount;

    @NotBlank(message = "Payment status is required")
    private String paymentStatus;


    @NotBlank(message = "Payment method is required")
    private String paymentMethod;

    @NotNull(message = "Payment date is required")
    private LocalDateTime paymentDate;
}

