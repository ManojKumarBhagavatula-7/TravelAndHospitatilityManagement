package com.travel.review1.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.travel.review1.entity.Review;

public interface ReviewRepository extends JpaRepository<Review, Integer> {
	List<Review> findByUserId(Integer userId);
	 
    List<Review> findByHotelId(Integer hotelId);
 
    List<Review> findByFlightId(Integer flightId);

}
