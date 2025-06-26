package com.travel.payment.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.travel.payment.entity.Payment;
import java.util.List;


public interface PaymentRepository extends JpaRepository<Payment, Integer> {

	//Optional<Payment> findByBooking_IdAndPayment_Status(Integer bookingId, String paymentStatus);
	
	Optional<Payment> findByBookingId(Integer bookingId);


	
}
