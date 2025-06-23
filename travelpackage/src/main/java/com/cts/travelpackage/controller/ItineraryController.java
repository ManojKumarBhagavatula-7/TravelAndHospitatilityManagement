package com.cts.travelpackage.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.cts.travelpackage.dto.ItineraryDto;
import com.cts.travelpackage.dto.ItineraryResponse;
import com.cts.travelpackage.dto.TopSellingPackageDto;
import com.cts.travelpackage.service.ItineraryService;
import com.cts.travelpackage.util.ItineraryAppConstants;

import jakarta.validation.Valid;

@RestController
@RequestMapping("api/v1/itineraries")
public class ItineraryController {
	
	private ItineraryService itineraryService;
	
	public ItineraryController(ItineraryService itineraryService) {
		this.itineraryService = itineraryService;
	}
	

	/**
	 * Creates a new itinerary.
	 *
	 * @param itineraryDto the itinerary details
	 * @return the created itinerary
	 */
	@PostMapping
	public ResponseEntity<ItineraryDto> createItinerary(@RequestBody @Valid ItineraryDto itineraryDto){
		return ResponseEntity.ok(itineraryService.createItinerary(itineraryDto));
	}
	
	

	/**
	 * Retrieves all itineraries with pagination and sorting.
	 *
	 * @param pageNo   the page number
	 * @param pageSize the page size
	 * @param sortBy   the field to sort by
	 * @param sortDir  the sort direction (asc/desc)
	 * @return paginated list of itineraries
	 */
	@GetMapping
	public ResponseEntity<ItineraryResponse> getAllItineraries(
			@RequestParam(value="pageNo",defaultValue=ItineraryAppConstants.DEFAULT_PAGE_NUMBER,required=false) int pageNo,
			@RequestParam(value="pageSize",defaultValue=ItineraryAppConstants.DEFAULT_PAGE_SIZE,required=false) int pageSize,
			@RequestParam(value="sortBy", defaultValue=ItineraryAppConstants.DEFAULT_SORT_BY,required = false) String sortBy,
			@RequestParam(value="sortDir", defaultValue=ItineraryAppConstants.DEFAULT_SORT_DIR,required = false) String sortDir
			){
		
		return new ResponseEntity<>(itineraryService.getAllItineraries(pageNo,pageSize,sortBy,sortDir),HttpStatus.OK);
	}
	
	

	/**
	 * Updates an itinerary by ID.
	 *
	 * @param id           the itinerary ID
	 * @param itineraryDto the updated itinerary details
	 * @return the updated itinerary
	 */

	@PutMapping("/{id}")
	public ResponseEntity<ItineraryDto> updateItineraryById(@PathVariable(name="id") Long id, @RequestBody ItineraryDto itineraryDto ){
		return new ResponseEntity<>(itineraryService.updateItineraryById(id,itineraryDto),HttpStatus.OK);
	}
	
	

	/**
	 * Retrieves an itinerary by ID.
	 *
	 * @param id the itinerary ID
	 * @return the itinerary
	 */
	@GetMapping("/{id}")
	public ResponseEntity<ItineraryDto> getItineraryById(@PathVariable(name="id") Long id ){
		return new ResponseEntity<>(itineraryService.getItineraryById(id),HttpStatus.CREATED);
	}
	
	

	/**
	 * Retrieves top-selling travel packages for dashboard display.
	 *
	 * @param limit the number of top packages to retrieve
	 * @return list of top-selling packages
	 */
	@GetMapping("/dashboard/topsellingpackages")
	public List<TopSellingPackageDto> getTopSellingPackages(@RequestParam(defaultValue = "5") int limit) {
	    return itineraryService.getTopSellingPackages(limit);
	}

	

}



