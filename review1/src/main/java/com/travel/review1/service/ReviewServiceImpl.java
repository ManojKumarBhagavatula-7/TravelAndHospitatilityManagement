package com.travel.review1.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.travel.review1.dao.ReviewDao;
import com.travel.review1.dto.ReviewDTO;
import com.travel.review1.entity.Review;

import jakarta.transaction.Transactional;

/**
 * Service implementation for handling review operations.
 */

@Service
public class ReviewServiceImpl implements ReviewService {

	private static final Logger logger = LoggerFactory.getLogger(ReviewServiceImpl.class);
	private ReviewDao reviewDao;

	public ReviewServiceImpl(ReviewDao reviewDao) {
		this.reviewDao = reviewDao;
	}

	/**
	 *      * Retrieves all reviews from the database.      *      * @return List of
	 * ReviewDTO     
	 */

	@Override
	@Transactional
	public List<ReviewDTO> getAllReviews() {
		logger.info("Retrieving all reviews from database");
		List<Review> allReviews = this.reviewDao.getAllReviews();
		if (allReviews != null && !allReviews.isEmpty()) {
			return allReviews.stream().map(this::mapReviewEntityToDTO).collect(Collectors.toList());
		}
		return null;

	}

	private ReviewDTO mapReviewEntityToDTO(Review review) {

		return ReviewDTO.builder().reviewId(review.getReviewId()).userId(review.getUserId())
				.hotelId(review.getHotelId()).flightId(review.getFlightId()).rating(review.getRating())
				.comment(review.getComment()).timestamp(review.getTimestamp()).createdBy(review.getCreatedBy())
				.createdDate(review.getCreatedDate()).updatedBy(review.getUpdatedBy())
				.updatedDate(review.getUpdatedDate()).build();

	}

	/**
	 *      * Retrieves reviews for a specific hotel.      *      * @param hotelId
	 * ID of the hotel      * @return List of ReviewDTO     
	 */

	@Override
	public List<ReviewDTO> getHotelReviews(Integer hotelId) {
		logger.info("Retrieving reviews for hotelId: {}", hotelId);
		List<Review> hotelReviews = this.reviewDao.getReviewsByHotelId(hotelId);
		if (hotelReviews != null && !hotelReviews.isEmpty()) {
			return hotelReviews.stream().map(this::mapReviewEntityToDTO).collect(Collectors.toList());
		}
		return null;
	}

	/**
	 *      * Posts a new review to the database.      *      * @param reviewDTO
	 * Review data      * @return ReviewDTO of the saved review     
	 */

	@Override
	public ReviewDTO postReview(ReviewDTO reviewDTO) {

		logger.info("Saving new review: {}", reviewDTO);

		Review review = this.reviewDao.saveReview(this.constructReviewEntityFromDTO(reviewDTO));
		return this.mapReviewEntityToDTO(review);

	}

	private Review constructReviewEntityFromDTO(ReviewDTO reviewDTO) {
		return Review.builder().userId(reviewDTO.getUserId())
				.hotelId(reviewDTO.getHotelId() != null ? reviewDTO.getHotelId() : null)
				.flightId(reviewDTO.getFlightId() != null ? reviewDTO.getFlightId() : null)
				.rating(reviewDTO.getRating()).comment(reviewDTO.getComment())
				.updatedBy(reviewDTO.getUserId().toString()).createdBy(reviewDTO.getUserId().toString())
				.timestamp(LocalDateTime.now()).createdDate(LocalDateTime.now()).updatedDate(LocalDateTime.now())
				.build();
	}

	/**
	 *      * Retrieves reviews for a specific flight.      *      * @param flightId
	 * ID of the flight      * @return List of ReviewDTO     
	 */

	@Override
	public List<ReviewDTO> getFlightReviews(Integer flightId) {
		logger.info("Retrieving reviews for flightId: {}", flightId);
		List<Review> flightReviews = this.reviewDao.getReviewsByFlightId(flightId);
		if (flightReviews != null && !flightReviews.isEmpty()) {
			return flightReviews.stream().map(this::mapReviewEntityToDTO).collect(Collectors.toList());
		}
		return null;
	}

}
