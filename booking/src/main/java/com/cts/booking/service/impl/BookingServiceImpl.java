package com.cts.booking.service.impl;

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

import com.cts.booking.dto.BookingDto;
import com.cts.booking.dto.BookingResponseDto;
import com.cts.booking.entity.Booking;
import com.cts.booking.exception.ResourceNotFoundException;
import com.cts.booking.repository.BookingRepository;
import com.cts.booking.service.BookingService;
import com.cts.booking.util.PaginationUtils;

@Service
public class BookingServiceImpl implements BookingService {

	BookingRepository bookingRepo;
	ModelMapper mapper;
	private static final Logger logger = LoggerFactory.getLogger(BookingServiceImpl.class);

	public BookingServiceImpl(BookingRepository bookingRepo, ModelMapper mapper) {
		this.bookingRepo = bookingRepo;
		this.mapper = mapper;
	}

	// entity to dto
	private BookingDto mapToDto(Booking booking) {

		return mapper.map(booking, BookingDto.class);
	}

	// dto to entity
	private Booking mapToEntity(BookingDto bookingDto) {
		return mapper.map(bookingDto, Booking.class);
	}

	@Override
	public BookingDto createBooking(BookingDto bookingDto) {

		Booking booking = mapToEntity(bookingDto);
		Booking newBooking = bookingRepo.save(booking);
		BookingDto response = mapToDto(newBooking);
		logger.info("new Booking is created with id {}", newBooking.getBookingId());

		return response;
	}

	@Override
	public BookingResponseDto getAllBookings(int pageNo, int pageSize, String sortBy, String sortDir) {
		logger.info("Fetching all bookings - page: {}, size: {}, sortBy: {}, sortDir: {}", pageNo, pageSize, sortBy, sortDir);
		Sort sort = sortDir.equalsIgnoreCase(Sort.Direction.ASC.name()) ? Sort.by(sortBy).ascending()
				: Sort.by(sortBy).descending();
		Pageable pageable = PageRequest.of(pageNo, pageSize, sort);

		Page<Booking> bookings = bookingRepo.findAll(pageable);

		List<Booking> listOfBookings = bookings.getContent();

		List<BookingDto> content = listOfBookings.stream().map(booking -> mapToDto(booking))
				.collect(Collectors.toList());

		BookingResponseDto response = new BookingResponseDto();

		response.setContent(content);
		response.setTotalPages(bookings.getTotalPages());
		response.setTotalElements(bookings.getTotalElements());
		response.setPageNo(bookings.getNumber());
		response.setPageSize(bookings.getSize());
		response.setFirst(bookings.isFirst());
		response.setLast(bookings.isLast());
		logger.info("Fetched {} bookings", content.size());
		return response;
	}

	@Override
	public BookingDto getBookingDetailsById(Long id) {
		logger.info("Fetching booking details for ID: {}", id);
		Booking booking = bookingRepo.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("Booking", "id", id));
		logger.info("booking details for ID Fetched: {}", id);

		return mapToDto(booking);

	}

	@Override
	public BookingDto updatePackageById(Long id, BookingDto bookingDto) {
		logger.info("Updating booking with ID: {}", id);
		Booking booking = bookingRepo.findById(id)
				.orElseThrow(() -> new ResourceNotFoundException("TravelPackage", "id", id));
		

		booking.setUserId(bookingDto.getUserId());
		booking.setType(bookingDto.getType());
		booking.setHotelId(bookingDto.getHotelId());
		booking.setFlightId(bookingDto.getFlightId());
		booking.setItineraryId(bookingDto.getItineraryId());
		booking.setStatus(bookingDto.getStatus());
		booking.setPaymentId(bookingDto.getPaymentId());

		Booking updatedBooking = bookingRepo.save(booking);
		logger.info("updated booking: {}", id);
		return mapToDto(updatedBooking);
	}

	@Override
	public BookingResponseDto getBookingsByUserId(Long userId, int pageNo, int pageSize, String sortBy, String sortDir) {
		logger.info("Fetching bookings for user ID: {}", userId);
		Sort sort = sortDir.equalsIgnoreCase(Sort.Direction.ASC.name()) 
	                ? Sort.by(sortBy).ascending() 
	                : Sort.by(sortBy).descending();

	    Pageable pageable = PageRequest.of(pageNo, pageSize, sort);
	    Page<Booking> bookingsPage = bookingRepo.findByUserId(userId, pageable);
	    logger.info("bookings for user ID is fetched: {}", userId);
	    return PaginationUtils.buildBookingResponse(bookingsPage, this::mapToDto);
	}
	
	
	@Override
	public BookingResponseDto getBookingsByType(String type, int pageNo, int pageSize, String sortBy, String sortDir) {
		logger.info("Fetching bookings by type: {}", type);
		Sort sort = sortDir.equalsIgnoreCase(Sort.Direction.ASC.name())
	            ? Sort.by(sortBy).ascending()
	            : Sort.by(sortBy).descending();

	    Pageable pageable = PageRequest.of(pageNo, pageSize, sort);
	    Page<Booking> bookingsPage = bookingRepo.findByTypeIgnoreCase(type, pageable);
	    logger.info("bookings by type fetched: {}", type);
	    return PaginationUtils.buildBookingResponse(bookingsPage, this::mapToDto);
	}

	@Override
	public BookingResponseDto getBookingsByStatus(String status, int pageNo, int pageSize, String sortBy, String sortDir) {
		logger.info("Fetching bookings by status: {}", status);
		Sort sort = sortDir.equalsIgnoreCase(Sort.Direction.ASC.name())
	            ? Sort.by(sortBy).ascending()
	            : Sort.by(sortBy).descending();

	    Pageable pageable = PageRequest.of(pageNo, pageSize, sort);
	    
	    Page<Booking> bookingsPage = bookingRepo.findByStatusIgnoreCase(status, pageable);
	    logger.info("bookings by status fetched: {}", status);
	    return PaginationUtils.buildBookingResponse(bookingsPage, this::mapToDto);
	}

	@Override
	public BookingResponseDto getActiveBookings(int pageNo, int pageSize, String sortBy, String sortDir) {
		logger.info("Fetching active bookings (CONFIRMED, IN_PROGRESS)");
		Sort sort = sortDir.equalsIgnoreCase(Sort.Direction.ASC.name())
	    		
	            ? Sort.by(sortBy).ascending()
	            : Sort.by(sortBy).descending();

	    Pageable pageable = PageRequest.of(pageNo, pageSize, sort);
	    Page<Booking> bookingsPage = bookingRepo.findByStatusIgnoreCaseIn(List.of("CONFIRMED", "IN_PROGRESS"), pageable);

	    return PaginationUtils.buildBookingResponse(bookingsPage, this::mapToDto);
	}


}
