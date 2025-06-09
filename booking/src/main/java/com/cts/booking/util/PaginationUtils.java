package com.cts.booking.util;

import com.cts.booking.dto.BookingDto;
import com.cts.booking.dto.BookingResponseDto;
import com.cts.booking.entity.Booking;
import org.springframework.data.domain.Page;

import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

public class PaginationUtils {

    public static BookingResponseDto buildBookingResponse(Page<Booking> bookingsPage, Function<Booking, BookingDto> mapper) {
        List<BookingDto> content = bookingsPage.getContent()
                .stream()
                .map(mapper)
                .collect(Collectors.toList());

        BookingResponseDto response = new BookingResponseDto();
        response.setContent(content);
        response.setTotalPages(bookingsPage.getTotalPages());
        response.setTotalElements(bookingsPage.getTotalElements());
        response.setPageNo(bookingsPage.getNumber());
        response.setPageSize(bookingsPage.getSize());
        response.setFirst(bookingsPage.isFirst());
        response.setLast(bookingsPage.isLast());

        return response;
    }
}
