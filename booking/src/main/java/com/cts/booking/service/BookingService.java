package com.cts.booking.service;

import java.util.List;

import com.cts.booking.dto.BookingDto;
import com.cts.booking.dto.BookingResponseDto;

public interface BookingService {
	
	BookingDto createBooking(BookingDto bookingDto);


	BookingResponseDto getAllBookings(int pageNo, int pageSize, String sortBy, String sortDir);


	BookingDto getBookingDetailsById(Long id);


	BookingDto updatePackageById(Long id, BookingDto bookingDto);
	
	BookingResponseDto getBookingsByUserId(Long userId,int pageNo, int pageSize, String sortBy, String sortDir);
	BookingResponseDto getBookingsByType(String type, int pageNo, int pageSize, String sortBy, String sortDir);
	BookingResponseDto getBookingsByStatus(String status, int pageNo, int pageSize, String sortBy, String sortDir);
	BookingResponseDto getActiveBookings(int pageNo, int pageSize, String sortBy, String sortDir);

}
