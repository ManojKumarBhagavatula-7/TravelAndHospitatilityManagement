package com.travel.review1.controller.model;

import com.travel.review1.dto.ReviewDTO;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PostReviewResponse {

	private ReviewDTO review;
}
