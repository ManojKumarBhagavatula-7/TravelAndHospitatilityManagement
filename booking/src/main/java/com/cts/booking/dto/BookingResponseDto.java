package com.cts.booking.dto;

import java.util.List;

import lombok.Data;


@Data
public class BookingResponseDto {

	private List<BookingDto> content;
	private int pageNo;
	private int pageSize;
	private long totalElements;
	private int totalPages;
	private boolean last;
	private boolean first;
}
