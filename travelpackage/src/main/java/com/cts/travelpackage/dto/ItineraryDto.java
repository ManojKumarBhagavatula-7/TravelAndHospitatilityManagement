package com.cts.travelpackage.dto;

import java.math.BigDecimal;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ItineraryDto {
	private Long itineraryId;

	@NotNull(message = "User ID cannot be null")
    private Long userId;
    private String customizationDetails;

    @NotNull(message = "Price cannot be null")
    @DecimalMin(value = "0.0", inclusive = false, message = "Price must be greater than zero")
    
    private BigDecimal price;
    @NotNull(message = "Travel Package ID cannot be null")
    private Long travelPackageId; // Reference to the TravelPackage entity
}




