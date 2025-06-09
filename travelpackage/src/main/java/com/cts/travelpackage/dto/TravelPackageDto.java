package com.cts.travelpackage.dto;

import java.math.BigDecimal;
import java.util.List;

import lombok.Data;

@Data
public class TravelPackageDto {

	private Long packageId;
	private String packageName;
	private List<Long> includedHotelIds;
	private List<Long> includedFlightIds;
	private List<String> activities;
	private BigDecimal price;
}
