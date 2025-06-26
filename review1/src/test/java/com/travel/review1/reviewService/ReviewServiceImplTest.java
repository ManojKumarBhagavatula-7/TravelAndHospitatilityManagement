package com.travel.review1.reviewService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import com.travel.review1.dao.ReviewDao;
import com.travel.review1.dto.ReviewDTO;
import com.travel.review1.entity.Review;
import com.travel.review1.service.ReviewServiceImpl;

public class ReviewServiceImplTest {
	
	@InjectMocks
	private ReviewServiceImpl reviewService;
	 
	@Mock
	private ReviewDao reviewDao;
	 
	private Review sampleReview;
	private ReviewDTO sampleDTO;
	 
	@BeforeEach
	public void setup() {
	    MockitoAnnotations.openMocks(this);
	 
	    sampleReview = Review.builder()
	            .reviewId(1)
	            .userId(10)
	            .hotelId(101)
	            .rating(5)
	            .comment("Great hotel")
	            .createdBy("10")
	            .updatedBy("10")
	.timestamp(LocalDateTime.now())
	.createdDate(LocalDateTime.now())
	.updatedDate(LocalDateTime.now())
	            .build();
	 
	    sampleDTO = ReviewDTO.builder()
	            .reviewId(1)
	            .userId(10)
	            .hotelId(101)
	            .rating(5)
	            .comment("Great hotel")
	            .createdBy("10")
	            .updatedBy("10")
	            .timestamp(sampleReview.getTimestamp())
	            .createdDate(sampleReview.getCreatedDate())
	            .updatedDate(sampleReview.getUpdatedDate())
	            .build();
	}
	 
	@Test
	public void testGetAllReviews_Success() {
	    when(reviewDao.getAllReviews()).thenReturn(List.of(sampleReview));
	    List<ReviewDTO> result = reviewService.getAllReviews();
	 
	    assertNotNull(result);
	    assertEquals(1, result.size());
	    assertEquals(sampleDTO.getUserId(), result.get(0).getUserId());
	    verify(reviewDao, times(1)).getAllReviews();
	}
	 
	@Test
	public void testGetAllReviews_EmptyList() {
	    when(reviewDao.getAllReviews()).thenReturn(Collections.emptyList());
	    List<ReviewDTO> result = reviewService.getAllReviews();
	    assertNull(result);
	    verify(reviewDao).getAllReviews();
	}
	 
	@Test
	public void testGetHotelReviews_Success() {
	    when(reviewDao.getReviewsByHotelId(101)).thenReturn(List.of(sampleReview));
	    List<ReviewDTO> result = reviewService.getHotelReviews(101);
	    assertNotNull(result);
	    assertEquals(1, result.size());
	    verify(reviewDao).getReviewsByHotelId(101);
	}
	 
	@Test
	public void testGetHotelReviews_Empty() {
	    when(reviewDao.getReviewsByHotelId(101)).thenReturn(Collections.emptyList());
	    List<ReviewDTO> result = reviewService.getHotelReviews(101);
	    assertNull(result);
	}
	 
	@Test
	public void testPostReview_Success() {
	    when(reviewDao.saveReview(any())).thenReturn(sampleReview);
	    ReviewDTO result = reviewService.postReview(sampleDTO);
	 
	    assertNotNull(result);
	    assertEquals(sampleDTO.getRating(), result.getRating());
	    verify(reviewDao).saveReview(any());
	}
	 
	@Test
	public void testGetFlightReviews_Success() {
	    when(reviewDao.getReviewsByFlightId(201)).thenReturn(List.of(sampleReview));
	    List<ReviewDTO> result = reviewService.getFlightReviews(201);
	    assertNotNull(result);
	    verify(reviewDao).getReviewsByFlightId(201);
	}
	 
	@Test
	public void testGetFlightReviews_Empty() {
	    when(reviewDao.getReviewsByFlightId(201)).thenReturn(Collections.emptyList());
	    List<ReviewDTO> result = reviewService.getFlightReviews(201);
	    assertNull(result);
	}
	 
	@Test
	public void testPostReview_Exception() {
	    when(reviewDao.saveReview(any())).thenThrow(new RuntimeException("DB error"));
	    assertThrows(RuntimeException.class, () -> reviewService.postReview(sampleDTO));
	}

}
