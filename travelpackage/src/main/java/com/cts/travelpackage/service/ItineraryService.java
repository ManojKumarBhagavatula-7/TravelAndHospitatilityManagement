package com.cts.travelpackage.service;

import java.util.List;

import com.cts.travelpackage.dto.ItineraryDto;
import com.cts.travelpackage.dto.ItineraryResponse;
import com.cts.travelpackage.dto.TopSellingPackageDto;

public interface ItineraryService {

	public ItineraryDto createItinerary(ItineraryDto itineraryDto);
	public ItineraryResponse getAllItineraries(int PageNo,int pageSize,String sortBy,String sortDir);
	public ItineraryDto getItineraryById(Long id);
	public ItineraryDto updateItineraryById(Long id, ItineraryDto itineraryDto);
	public List<TopSellingPackageDto> getTopSellingPackages(int limit);

	
}
