package com.travel.review1.controller;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.travel.review1.controller.model.PostReviewRequest;
import com.travel.review1.controller.model.PostReviewResponse;
import com.travel.review1.controller.model.ReviewResponse;
import com.travel.review1.dto.ReviewDTO;
import com.travel.review1.service.ReviewService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

/**
 * Controller for handling review-related endpoints.
 */

@RestController
public class ReviewController {
	private static final Logger logger = LoggerFactory.getLogger(ReviewController.class);
	private ReviewService reviewServiceImpl;

	public ReviewController(ReviewService reviewServiceImpl) {
		this.reviewServiceImpl = reviewServiceImpl;
	}

	/**
	 *      * Retrieves all reviews.      *     
	 * @return ResponseEntity containing
	 * all reviews     
	 */

	@GetMapping(path = "/reviews")
	public ResponseEntity<ReviewResponse> getAllReviews() {
		logger.info("Fetching all reviews");
		List<ReviewDTO> reviews = this.reviewServiceImpl.getAllReviews();
		return new ResponseEntity<ReviewResponse>(ReviewResponse.builder().reviews(reviews).build(), HttpStatus.OK);

	}

	/**
	 *      
	 *  Retrieves reviews for a specific hotel.      
	 *  @param hotelId
	 * ID of the hotel      
	 * @return ResponseEntity containing hotel reviews     
	 */

	@GetMapping(path = "/reviews/hotel/{hotelId}")
	public ResponseEntity<ReviewResponse> getHotelReviews(
			@NotNull(message = "Please provide hotel id as path variable") @PathVariable(name = "hotelId") Integer hotelId) {

		logger.info("Fetching reviews for hotelId: {}", hotelId);

		List<ReviewDTO> reviews = this.reviewServiceImpl.getHotelReviews(hotelId);

		return new ResponseEntity<ReviewResponse>(ReviewResponse.builder().reviews(reviews).build(), HttpStatus.OK);

	}

	/**
	 *Retrieves reviews for a specific flight. 
	 * @param flightId
	 * ID of the flight      * @return ResponseEntity containing flight reviews     
	 */

	@GetMapping(path = "/reviews/flight/{flightId}")
	public ResponseEntity<ReviewResponse> getFlightReviews(
			@NotNull(message = "Please provide flight id as path variable") @PathVariable(name = "flightId") Integer flightId) {
		logger.info("Fetching reviews for flightId: {}", flightId);
		List<ReviewDTO> reviews = this.reviewServiceImpl.getFlightReviews(flightId);

		return new ResponseEntity<ReviewResponse>(ReviewResponse.builder().reviews(reviews).build(), HttpStatus.OK);

	}

	/**
	 * Posts a new review for either a hotel or a flight.      *     
	 * * @param postReviewRequest Request body containing review details     
	 * * @return ResponseEntity containing the posted review      * @throws
	 * Exception if both hotelId and flightId are provided     
	 */

	@PostMapping(path = "/review")
	public ResponseEntity<PostReviewResponse> postHotelReview(@Valid @RequestBody PostReviewRequest postReviewRequest)
			throws Exception {
		logger.info("Posting a new review: {}", postReviewRequest);
		if ((postReviewRequest.getFlightId() != null && postReviewRequest.getHotelId() != null)) {

			logger.error("Both flightId and hotelId provided. Only one is allowed.");

			throw new Exception("Please send either Flight Id or Hotel Id");
		}
		ReviewDTO reviewDTO = ReviewDTO.builder().userId(postReviewRequest.getUserId())
				.hotelId(postReviewRequest.getHotelId()).flightId(postReviewRequest.getFlightId())
				.comment(postReviewRequest.getComment()).rating(postReviewRequest.getRating()).build();
		ReviewDTO postedReview = this.reviewServiceImpl.postReview(reviewDTO);
		return new ResponseEntity<PostReviewResponse>(PostReviewResponse.builder().review(postedReview).build(),
				HttpStatus.CREATED);
	}

}
