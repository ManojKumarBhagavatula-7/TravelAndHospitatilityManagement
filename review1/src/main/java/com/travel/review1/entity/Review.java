package com.travel.review1.entity;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "Review")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Review {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "Review_ID")
	private Integer reviewId;

	@Column(name = "User_ID", nullable = false)
	private Integer userId;

	@Column(name = "Hotel_ID")
	private Integer hotelId;

	@Column(name = "Flight_ID")
	private Integer flightId;

	@Column(name = "Rating")
	private Integer rating;

	@Column(name = "Comment")
	private String comment;

	@Column(updatable = false)
	private LocalDateTime timestamp = LocalDateTime.now();

	@Column(name = "Created_Date", updatable = false)
	private LocalDateTime createdDate = LocalDateTime.now();

	@Column(name = "Created_By")
	private String createdBy;

	@Column(name = "Updated_Date")
	private LocalDateTime updatedDate = LocalDateTime.now();

	@Column(name = "Updated_By")
	private String updatedBy;

	@PreUpdate
	public void preUpdate() {
		this.updatedDate = LocalDateTime.now();
		this.createdDate = LocalDateTime.now();
		this.timestamp = LocalDateTime.now();
	}

}
