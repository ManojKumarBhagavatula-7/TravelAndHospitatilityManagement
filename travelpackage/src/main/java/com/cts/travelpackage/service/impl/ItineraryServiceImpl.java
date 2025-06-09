package com.cts.travelpackage.service.impl;

import java.util.List;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import com.cts.travelpackage.dto.ItineraryDto;
import com.cts.travelpackage.dto.ItineraryResponse;
import com.cts.travelpackage.dto.TopSellingPackageDto;
import com.cts.travelpackage.entity.Itinerary;
import com.cts.travelpackage.entity.TravelPackage;
import com.cts.travelpackage.exception.ResourceNotFoundException;
import com.cts.travelpackage.repository.ItineraryRepository;
import com.cts.travelpackage.repository.PackageRepository;
import com.cts.travelpackage.service.ItineraryService;

@Service
public class ItineraryServiceImpl implements ItineraryService{
	
	
	private ItineraryRepository itineraryRepo;
	private PackageRepository packageRepo;
	private ModelMapper mapper;
	private static final Logger logger =LoggerFactory.getLogger(ItineraryServiceImpl.class);
	
	public ItineraryServiceImpl(ItineraryRepository itineraryRepo,ModelMapper mapper, PackageRepository packageRepo) {
		this.itineraryRepo = itineraryRepo;
		this.mapper = mapper;
		this.packageRepo = packageRepo;
	}
	
	private Itinerary mapToEntity(ItineraryDto itineraryDto) {
		return mapper.map(itineraryDto, Itinerary.class);
	}
	
	private ItineraryDto mapToDto(Itinerary itinerary) {
		return mapper.map(itinerary, ItineraryDto.class);
	}

	/**
	 * {@inheritDoc}
	 */

	@Override
	public ItineraryDto createItinerary(ItineraryDto itineraryDto) {
		logger.info("Creating new itinerary for user ID: {}", itineraryDto.getUserId());
		Itinerary itinerary = mapToEntity(itineraryDto);

		Itinerary newItinerary = itineraryRepo.save(itinerary);
		logger.info("Itinerary created with ID: {}", newItinerary.getItineraryId());
		return mapToDto(newItinerary);
	}


	/**
	 * {@inheritDoc}
	 */

	@Override
	public ItineraryResponse getAllItineraries(int pageNo,int pageSize,String sortBy,String sortDir) {

		logger.info("Fetching itineraries - page: {}, size: {}, sortBy: {}, sortDir: {}", pageNo, pageSize, sortBy, sortDir);

		Sort sort = sortDir.equalsIgnoreCase(Sort.Direction.ASC.name())
					?Sort.by(sortBy).ascending()
					:Sort.by(sortBy).descending();
		Pageable pageable = PageRequest.of(pageNo, pageSize,sort);
		Page<Itinerary> itineraries = itineraryRepo.findAll(pageable);
		List<Itinerary> listOfItineraries = itineraries.getContent();
		List<ItineraryDto> content = listOfItineraries == null ? 
			    						List.of() : 
			    						listOfItineraries.stream()
			    						.map(this::mapToDto)
			    						.toList();

		
		ItineraryResponse response = new ItineraryResponse();
		
		response.setContent(content);
		response.setTotalPages(itineraries.getTotalPages());
		response.setTotalElements(itineraries.getTotalElements());
		response.setPageNo(itineraries.getNumber());
		response.setPageSize(itineraries.getSize());
		response.setFirst(itineraries.isFirst());
		response.setLast(itineraries.isLast());
		logger.info("Fetched {} itineraries", content.size());
		return response;
	}

	/**
	 * {@inheritDoc}
	 */

	@Override
	public ItineraryDto getItineraryById(Long id) {
		logger.info("Fetching itinerary with ID: {}", id);
		Itinerary itinerary = itineraryRepo.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("Itinerary","id",id));
		return mapToDto(itinerary);
	}


	/**
	 * {@inheritDoc}
	 */

	@Override
	public ItineraryDto updateItineraryById(Long id, ItineraryDto itineraryDto) {
		logger.info("Updating itinerary with ID: {}", id);
		Itinerary itinerary = itineraryRepo.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("Itinerary","id",id));
		
		itinerary.setUserId(itineraryDto.getUserId());
		itinerary.setCustomizationDetails(itineraryDto.getCustomizationDetails());
		itinerary.setPrice(itineraryDto.getPrice());
		TravelPackage travelPackage = packageRepo.findById(itineraryDto.getTravelPackageId())
		        .orElseThrow(() -> new ResourceNotFoundException("TravelPackage", "id", itineraryDto.getTravelPackageId()));
		    itinerary.setTravelPackage(travelPackage);

		    Itinerary updatedItinerary = itineraryRepo.save(itinerary);
		    logger.info("Successfully updated itinerary with ID: {}", id);
		    return mapToDto(updatedItinerary);
		
	}

	/**
	 * {@inheritDoc}
	 */
	public List<TopSellingPackageDto> getTopSellingPackages(int limit) {
		logger.info("Fetching top {} selling packages", limit);
	    Pageable pageable = PageRequest.of(0, limit);
	    List<TopSellingPackageDto> results = itineraryRepo.findTopSellingPackagesWithDetails(pageable);
	    logger.info("Top selling packages fetched: {}", results.size());
	    return results;
	}


}




