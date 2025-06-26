package com.travel.review1.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.springframework.http.MediaType;

import java.time.LocalDateTime;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.travel.review1.controller.model.PostReviewRequest;
import com.travel.review1.dto.ReviewDTO;
import com.travel.review1.service.ReviewService;

@WebMvcTest(ReviewController.class)
public class ReviewControllerTest {
	
	@Autowired
	private MockMvc mockMvc;
	 
	@MockBean
	private ReviewService reviewService;
	 
	@Autowired
	private ObjectMapper objectMapper;
	 
	private ReviewDTO reviewDTO;
	 
	@BeforeEach
	void setUp() {
	    reviewDTO = ReviewDTO.builder()
	            .reviewId(1)
	            .userId(10)
	            .hotelId(101)
	            .rating(4)
	            .comment("Nice stay")
	            .createdBy("10")
	            .updatedBy("10")
	.timestamp(LocalDateTime.now())
	.createdDate(LocalDateTime.now())
	.updatedDate(LocalDateTime.now())
	            .build();
	}
	 
	@Test
	void testGetAllReviews_Success() throws Exception {
	    when(reviewService.getAllReviews()).thenReturn(List.of(reviewDTO));
	 
	    mockMvc.perform(get("/reviews"))
	            .andExpect(status().isOk())
	            .andExpect(jsonPath("$.reviews[0].userId").value(10));
	}
	 
	@Test
	void testGetHotelReviews_Success() throws Exception {
	    when(reviewService.getHotelReviews(101)).thenReturn(List.of(reviewDTO));
	 
	    mockMvc.perform(get("/reviews/hotel/101"))
	            .andExpect(status().isOk())
	            .andExpect(jsonPath("$.reviews[0].hotelId").value(101));
	}
	 
	@Test
	void testGetFlightReviews_Success() throws Exception {
	    when(reviewService.getFlightReviews(201)).thenReturn(List.of(reviewDTO));
	 
	    mockMvc.perform(get("/reviews/flight/201"))
	            .andExpect(status().isOk())
	            .andExpect(jsonPath("$.reviews[0].flightId").doesNotExist());
	}
	 
	@Test
	void testPostReview_Success() throws Exception {
	    PostReviewRequest request = PostReviewRequest.builder()
	            .userId(10)
	            .hotelId(101)
	            .rating(5)
	            .comment("Wonderful")
	            .build();
	 
	    when(reviewService.postReview(any())).thenReturn(reviewDTO);
	 
	    mockMvc.perform(post("/review")
	                    .contentType(MediaType.APPLICATION_JSON)
	                    .content(objectMapper.writeValueAsString(request)))
	            .andExpect(status().isCreated())
	            .andExpect(jsonPath("$.review.userId").value(10));
	}
	 
	@Test
	void testPostReview_BothHotelAndFlightIdsProvided() throws Exception {
	    PostReviewRequest request = PostReviewRequest.builder()
	            .userId(10)
	            .hotelId(101)
	            .flightId(202)
	            .rating(4)
	            .build();
	 
	    mockMvc.perform(post("/review")
	                    .contentType(MediaType.APPLICATION_JSON)
	                    .content(objectMapper.writeValueAsString(request)))
	            .andExpect(status().isInternalServerError())
	            .andExpect(jsonPath("$.message").value("An unexpected error occurred => Please send either Flight Id or Hotel Id"));
	}
	 
	@Test
	void testPostReview_MissingRequiredField() throws Exception {
	    PostReviewRequest request = PostReviewRequest.builder()
	            .hotelId(101)
	            .rating(5)
	            .build();
	 
	    mockMvc.perform(post("/review")
	                    .contentType(MediaType.APPLICATION_JSON)
	                    .content(objectMapper.writeValueAsString(request)))
	            .andExpect(status().isBadRequest())
	            .andExpect(jsonPath("$.errors.userId").value("User Id is required"));
	}

}
