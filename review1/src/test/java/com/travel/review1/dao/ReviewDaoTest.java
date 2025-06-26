package com.travel.review1.dao;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import com.travel.review1.entity.Review;
import com.travel.review1.repository.ReviewRepository;

public class ReviewDaoTest {

	
	@InjectMocks
	private ReviewDao reviewDao;
	 
	@Mock
	private ReviewRepository reviewRepository;
	 
	private Review sampleReview;
	 
	@BeforeEach
	void setUp() {
	    MockitoAnnotations.openMocks(this);
	 
	    sampleReview = Review.builder()
	            .reviewId(1)
	            .userId(10)
	            .hotelId(100)
	            .rating(5)
	            .comment("Excellent stay")
	.timestamp(LocalDateTime.now())
	.createdDate(LocalDateTime.now())
	.updatedDate(LocalDateTime.now())
	            .createdBy("10")
	            .updatedBy("10")
	            .build();
	}
	 
	@Test
	void testSaveReview() {
	when(reviewRepository.save(sampleReview)).thenReturn(sampleReview);
	    Review saved = reviewDao.saveReview(sampleReview);
	    assertNotNull(saved);
	    assertEquals(sampleReview.getReviewId(), saved.getReviewId());
	}
	 
	@Test
	void testGetReviewById_Found() {
	    when(reviewRepository.findById(1)).thenReturn(Optional.of(sampleReview));
	    Optional<Review> result = reviewDao.getReviewById(1);
	    assertTrue(result.isPresent());
	    assertEquals(10, result.get().getUserId());
	}
	 
	@Test
	void testGetReviewById_NotFound() {
	    when(reviewRepository.findById(99)).thenReturn(Optional.empty());
	    Optional<Review> result = reviewDao.getReviewById(99);
	    assertTrue(result.isEmpty());
	}
	 
	@Test
	void testGetAllReviews() {
	    when(reviewRepository.findAll()).thenReturn(Arrays.asList(sampleReview));
	    List<Review> result = reviewDao.getAllReviews();
	    assertEquals(1, result.size());
	}
	 
	@Test
	void testGetReviewsByUserId() {
	    when(reviewRepository.findByUserId(10)).thenReturn(List.of(sampleReview));
	    List<Review> result = reviewDao.getReviewsByUserId(10);
	    assertEquals(1, result.size());
	}
	 
	@Test
	void testGetReviewsByHotelId() {
	    when(reviewRepository.findByHotelId(100)).thenReturn(List.of(sampleReview));
	    List<Review> result = reviewDao.getReviewsByHotelId(100);
	    assertEquals(1, result.size());
	}
	 
	@Test
	void testGetReviewsByFlightId() {
	    when(reviewRepository.findByFlightId(200)).thenReturn(List.of(sampleReview));
	    List<Review> result = reviewDao.getReviewsByFlightId(200);
	    assertEquals(1, result.size());
	}
	 
	@Test
	void testExistsById_True() {
	    when(reviewRepository.existsById(1)).thenReturn(true);
	    assertTrue(reviewDao.existsById(1));
	}
	 
	@Test
	void testExistsById_False() {
	    when(reviewRepository.existsById(2)).thenReturn(false);
	    assertFalse(reviewDao.existsById(2));
	}
}
