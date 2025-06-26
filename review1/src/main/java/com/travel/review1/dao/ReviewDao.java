package com.travel.review1.dao;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.travel.review1.entity.Review;
import com.travel.review1.repository.ReviewRepository;

@Component
public class ReviewDao {
	@Autowired
    private ReviewRepository reviewRepository;
 
    public Review saveReview(Review review) {
    	return this.reviewRepository.save(review);
    }
 
    public Optional<Review> getReviewById(Integer reviewId) {
        return this.reviewRepository.findById(reviewId);
    }
 
    public  List<Review> getAllReviews() {
        return this.reviewRepository.findAll();
    }
 
    public List<Review> getReviewsByUserId(Integer userId) {
        return this.reviewRepository.findByUserId(userId);
    }
 
    public List<Review> getReviewsByHotelId(Integer hotelId) {
        return this.reviewRepository.findByHotelId(hotelId);
    }
 
    public List<Review> getReviewsByFlightId(Integer flightId) {
        return this.reviewRepository.findByFlightId(flightId);
    }
 
    public boolean existsById(Integer reviewId) {
        return this.reviewRepository.existsById(reviewId);
    }

}
