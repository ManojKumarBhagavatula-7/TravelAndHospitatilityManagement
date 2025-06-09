package com.cts.booking.dto;


import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class BookingDto {

//    @NotNull(message = "Booking ID cannot be null")
    private Long bookingId;

    @NotNull(message = "User ID cannot be null")
    private Long userId;

    @NotBlank(message = "Type cannot be blank")
    private String type;

   
    private Long hotelId;

    
    private Long flightId;

    private Long itineraryId;

    @NotBlank(message = "Status cannot be blank")
    private String status;

    @NotNull(message = "Payment ID cannot be null")
    private Long paymentId;
}

