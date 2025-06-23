package com.cts.travelpackage.controller;

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

import com.cts.travelpackage.dto.TravelPackageDto;
import com.cts.travelpackage.dto.TravelPackageResponse;
import com.cts.travelpackage.service.PackageService;
import com.cts.travelpackage.util.AppConstants;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("api/v1/packages")
@Slf4j
public class PackageController {

	private PackageService packageService;
	
	public PackageController( PackageService packageService) {
		this.packageService = packageService;
	}
	

	/**
	 * Creates a new travel package.
	 *
	 * @param travelpackageDto the travel package details
	 * @return the created travel package
	 */
	@PostMapping
	public ResponseEntity<TravelPackageDto> createPackage( @RequestBody @Valid TravelPackageDto travelpackageDto) {

		log.info("Received request to create a new travel package");
		return new ResponseEntity<>(packageService.createPackage(travelpackageDto),HttpStatus.CREATED);
	
	}
	
	

	/**
	 * Retrieves all travel packages with pagination and sorting.
	 *
	 * @param pageNo   the page number
	 * @param pageSize the page size
	 * @param sortBy   the field to sort by
	 * @param sortDir  the sort direction (asc/desc)
	 * @return paginated list of travel packages
	 */
	@GetMapping
	public ResponseEntity<TravelPackageResponse> getAllPackages(
			@RequestParam(value="pageNo",defaultValue=AppConstants.DEFAULT_PAGE_NUMBER,required=false) int pageNo,
			@RequestParam(value="pageSize",defaultValue=AppConstants.DEFAULT_PAGE_SIZE,required=false) int pageSize,
			@RequestParam(value="sortBy", defaultValue=AppConstants.DEFAULT_SORT_BY,required = false) String sortBy,
			@RequestParam(value="sortDir", defaultValue=AppConstants.DEFAULT_SORT_DIR,required = false) String sortDir

			){
		log.info("Fetching all travel packages - page: {}, size: {}, sortBy: {}, sortDir: {}",pageNo, pageSize, sortBy, sortDir);
		return new ResponseEntity<>(packageService.getAllPackages(pageNo,pageSize,sortBy,sortDir),HttpStatus.OK);
		
	}
	
	

	/**
	 * Retrieves a travel package by its ID.
	 *
	 * @param id the package ID
	 * @return the travel package
	 */
	@GetMapping("/{id}")
	public ResponseEntity<TravelPackageDto> getPackageById(@PathVariable(name="id") Long id) {

		log.info("Fetching travel package with ID: {}", id);

		return ResponseEntity.ok(packageService.getPackageById(id));
	}
	
	

	/**
	 * Updates a travel package by its ID.
	 *
	 * @param id               the package ID
	 * @param travelPackageDto the updated package details
	 * @return the updated travel package
	 */
	@PutMapping("/{id}")
	public ResponseEntity<TravelPackageDto> updatePackageById(@PathVariable(name="id") Long id,@RequestBody @Valid TravelPackageDto travelPackageDto) {

		log.info("Updating travel package with ID: {}", id);

		TravelPackageDto response = packageService.updatePackageById(id, travelPackageDto);
		return ResponseEntity.ok(response);
	}
	
}
