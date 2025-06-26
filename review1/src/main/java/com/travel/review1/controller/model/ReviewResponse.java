package com.travel.review1.controller.model;

import java.util.List;

import com.travel.review1.dto.ReviewDTO;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ReviewResponse {
	
	private List<ReviewDTO> reviews;
	 

}
