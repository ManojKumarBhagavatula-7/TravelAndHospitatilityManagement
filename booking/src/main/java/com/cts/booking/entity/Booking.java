package com.cts.booking.entity;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import com.cts.booking.entity.base.Auditable;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Entity
@Data
@EqualsAndHashCode(callSuper = false)
@AllArgsConstructor
@NoArgsConstructor
@Table(name="booking")
@EnableJpaAuditing
public class Booking extends Auditable<String>{
	
	@Id
	@GeneratedValue(strategy=GenerationType.IDENTITY)
	@Column(name="booking_id")
	private Long bookingId;
	
	@Column(name="user_id",nullable=false)
	private Long userId;
	
	@Column(name="type")
	private String type;
	
	@Column(name="hotel_id")
	private Long hotelId;
	
	@Column(name="flight_id")
	private Long flightId;
	
	@Column(name="itinerary_id")
	private Long itineraryId;
	
	@Column(name="status",nullable=false)
	private String status;
	
	@Column(name="payment_id",nullable=false)
	private Long paymentId;

}
