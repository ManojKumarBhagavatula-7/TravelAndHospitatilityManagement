package com.travel.review1.controller.model;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PostReviewRequest {

	@NotNull(message = "User Id is required")
	private Integer userId;
	private Integer hotelId;
	private Integer flightId;

	@NotNull(message = "Rating is required")
	private Integer rating;

	private String comment;
}
