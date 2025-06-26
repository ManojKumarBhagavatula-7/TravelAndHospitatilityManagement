package com.travel.review1.service;

import java.util.List;

import com.travel.review1.dto.ReviewDTO;

public interface ReviewService {

	List<ReviewDTO> getAllReviews();
	List<ReviewDTO> getHotelReviews(Integer hotelId);
	List<ReviewDTO> getFlightReviews(Integer flightId);
	ReviewDTO postReview(ReviewDTO reviewDTO);
}
