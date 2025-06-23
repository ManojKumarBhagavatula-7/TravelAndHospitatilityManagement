package com.cts.booking.controller;

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

import com.cts.booking.dto.BookingDto;
import com.cts.booking.dto.BookingResponseDto;
import com.cts.booking.service.BookingService;
import com.cts.booking.util.AppConstants;


import jakarta.validation.Valid;

@RestController
@RequestMapping("api/v1/bookings")
public class BookingController {

	private BookingService bookingService;

	public BookingController(BookingService bookingService) {
		this.bookingService = bookingService;
	}


	/**
     * Creates a new booking.
     *
     * @param bookingDto the booking details to be created
     * @return the created booking with generated ID
     */

	@PostMapping
	public ResponseEntity<BookingDto> createBooking(@Valid @RequestBody BookingDto bookingDto) {
		return new ResponseEntity<>(bookingService.createBooking(bookingDto), HttpStatus.CREATED);
	}


	/**
     * Retrieves all bookings with pagination and sorting.
     *
     * @param pageNo   the page number to retrieve
     * @param pageSize the number of records per page
     * @param sortBy   the field to sort by
     * @param sortDir  the direction of sorting (asc/desc)
     * @return paginated list of bookings
     */

	@GetMapping
	public ResponseEntity<BookingResponseDto> getAllBookings(
			@RequestParam(value="pageNo",defaultValue=AppConstants.DEFAULT_PAGE_NUMBER,required=false) int pageNo,
			@RequestParam(value="pageSize",defaultValue=AppConstants.DEFAULT_PAGE_SIZE,required=false) int pageSize,
			@RequestParam(value="sortBy", defaultValue=AppConstants.DEFAULT_SORT_BY,required = false) String sortBy,
			@RequestParam(value="sortDir", defaultValue=AppConstants.DEFAULT_SORT_DIR,required = false) String sortDir
			){
	return new ResponseEntity<>(bookingService.getAllBookings(pageNo,pageSize,sortBy,sortDir),HttpStatus.OK);
	}
	

	/**
     * Retrieves booking details by booking ID.
     *
     * @param id the ID of the booking
     * @return the booking details
     */

	@GetMapping("/{id}")
	public ResponseEntity<BookingDto> getBookingDetailsById(@PathVariable Long id){
		return new ResponseEntity<>(bookingService.getBookingDetailsById(id),HttpStatus.OK);
	}
	
	

	/**
     * Updates a booking by its ID.
     *
     * @param id         the ID of the booking to update
     * @param bookingDto the updated booking details
     * @return the updated booking
     */
	@PutMapping("/{id}")
	public ResponseEntity<BookingDto> updateBookingById(@PathVariable Long id, @RequestBody BookingDto bookingDto){
		BookingDto response = bookingService.updatePackageById(id, bookingDto);
		return ResponseEntity.ok(response);
	}
	


	/**
     * Retrieves bookings made by a specific user.
     *
     * @param userId   the ID of the user
     * @param pageNo   the page number
     * @param pageSize the number of records per page
     * @param sortBy   the field to sort by
     * @param sortDir  the direction of sorting
     * @return paginated list of bookings for the user
     */
	@GetMapping("/user/{userId}")
	public ResponseEntity<BookingResponseDto> getBookingsByUserId(
					@PathVariable Long userId,
					@RequestParam(value="pageNo",defaultValue=AppConstants.DEFAULT_PAGE_NUMBER,required=false) int pageNo,
					@RequestParam(value="pageSize",defaultValue=AppConstants.DEFAULT_PAGE_SIZE,required=false) int pageSize,
					@RequestParam(value="sortBy", defaultValue=AppConstants.DEFAULT_SORT_BY,required = false) String sortBy,
					@RequestParam(value="sortDir", defaultValue=AppConstants.DEFAULT_SORT_DIR,required = false) String sortDir
					
				) 
	{
			BookingResponseDto response = bookingService.getBookingsByUserId(userId, pageNo, pageSize, sortBy, sortDir);
			return ResponseEntity.ok(response);
	}
	
	

	/**
     * Retrieves bookings filtered by booking type.
     *
     * @param type     the type of booking (e.g., "flight", "hotel")
     * @param pageNo   the page number
     *  @param sortBy   the field to sort by
     * @param sortDir  the direction of sorting
     * @return paginated list of bookings by type
     */

    @GetMapping("/type/{type}")
    public ResponseEntity<BookingResponseDto> getBookingsByType(
            @PathVariable String type,
			@RequestParam(value="pageNo",defaultValue=AppConstants.DEFAULT_PAGE_NUMBER,required=false) int pageNo,
			@RequestParam(value="pageSize",defaultValue=AppConstants.DEFAULT_PAGE_SIZE,required=false) int pageSize,
			@RequestParam(value="sortBy", defaultValue=AppConstants.DEFAULT_SORT_BY,required = false) String sortBy,
			@RequestParam(value="sortDir", defaultValue=AppConstants.DEFAULT_SORT_DIR,required = false) String sortDir
			
    ) {
        BookingResponseDto response = bookingService.getBookingsByType(type, pageNo, pageSize, sortBy, sortDir);
        return ResponseEntity.ok(response);
    }


    /**
     * Retrieves bookings filtered by booking status.
     *
     * @param status   the status of the booking (e.g., "confirmed", "cancelled")
     * @param pageNo   the page number
     * @param pageSize the number of records per page
     * @param sortBy   the field to sort by
     * @param sortDir  the direction of sorting
     * @return paginated list of bookings by status
     */

    @GetMapping("/status/{status}")
    public ResponseEntity<BookingResponseDto> getBookingsByStatus(
            @PathVariable String status,
            @RequestParam(value="pageNo",defaultValue=AppConstants.DEFAULT_PAGE_NUMBER,required=false) int pageNo,
			@RequestParam(value="pageSize",defaultValue=AppConstants.DEFAULT_PAGE_SIZE,required=false) int pageSize,
			@RequestParam(value="sortBy", defaultValue=AppConstants.DEFAULT_SORT_BY,required = false) String sortBy,
			@RequestParam(value="sortDir", defaultValue=AppConstants.DEFAULT_SORT_DIR,required = false) String sortDir
			
    ) {
        BookingResponseDto response = bookingService.getBookingsByStatus(status, pageNo, pageSize, sortBy, sortDir);
        return ResponseEntity.ok(response);
    }


	/**
	     * Retrieves all active bookings.
	     *
	     * @param pageNo   the page number
	     * @param pageSize the number of records per page
	     * @param sortBy   the field to sort by
	     * @return paginated list of active bookings
	     */
    
	@GetMapping("/active")
	public ResponseEntity<BookingResponseDto> getActiveBookings(
			@RequestParam(value="pageNo",defaultValue=AppConstants.DEFAULT_PAGE_NUMBER,required=false) int pageNo,
			@RequestParam(value="pageSize",defaultValue=AppConstants.DEFAULT_PAGE_SIZE,required=false) int pageSize,
			@RequestParam(value="sortBy", defaultValue=AppConstants.DEFAULT_SORT_BY,required = false) String sortBy,
			@RequestParam(value="sortDir", defaultValue=AppConstants.DEFAULT_SORT_DIR,required = false) String sortDir
			
	) {
	    BookingResponseDto response = bookingService.getActiveBookings(pageNo, pageSize, sortBy, sortDir);
	    return ResponseEntity.ok(response);
	}
}


