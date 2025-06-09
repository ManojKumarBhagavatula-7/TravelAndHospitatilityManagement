package com.cts.travelpackage.dto;

import java.math.BigDecimal;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ItineraryDto {
	private Long itineraryId;
    private Long userId;
    private String customizationDetails;
    private BigDecimal price;
    private Long travelPackageId; // Reference to the TravelPackage entity
}




