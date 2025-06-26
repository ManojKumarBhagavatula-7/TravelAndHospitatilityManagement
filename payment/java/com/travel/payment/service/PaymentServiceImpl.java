package com.travel.payment.service;

import java.security.PublicKey;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.travel.payment.dao.PaymentDAO;
import com.travel.payment.dto.PaymentDTO;
import com.travel.payment.entity.Payment;
import com.travel.payment.exceptions.DuplicatePaymentException;
import com.travel.payment.repository.PaymentRepository;

import jakarta.transaction.Transactional;

/**
 * Service implementation for managing payment operations.
 */

@Service
public class PaymentServiceImpl{
	private static final Logger logger = LoggerFactory.getLogger(PaymentServiceImpl.class);
	
	

	@Autowired
	private PaymentDAO paymentDao;
	@Autowired
	private PaymentRepository paymentRepository;

	/**
     * Stores a new payment in the database.
     *
     * @param paymentDto the payment data to store
     * @return the stored PaymentDTO
     */
     
	@Transactional
	public PaymentDTO storePayment(PaymentDTO paymentDto) {
		logger.info("{}",paymentDto);
		logger.info("{}",paymentDto.getBookingId());
		
		Optional<Payment> existingPayment = paymentRepository.findByBookingId(paymentDto.getBookingId());
		  
		if (existingPayment.isPresent()) {
		    throw new DuplicatePaymentException("Payment already exists with this booking ID : " + paymentDto.getBookingId());
		}

		
//		Payment exisitingPayment = paymentRepository.findById(paymentDto.getBookingId())
//									.orElseThrow(()-> new DuplicatePaymentException("Payment already exists with this booking ID : "+paymentDto.getBookingId()));
//		logger.info("Existing {}",exisitingPayment);
////		if(exisitingPayment.isPresent()) {
////			throw new DuplicatePaymentException("Payment already exists with this booking ID : "+paymentDto.getBookingId());
////		}
		logger.info("Storing payment for bookingId: {}", paymentDto.getBookingId());
		return this.paymentDao.insertPayment(paymentDto);

	}
	
	/**
	     * Retrieves all payments from the database.
	     *
	     * @return list of PaymentDTOs
	     */
	@Transactional
	public List<PaymentDTO> getAllPayments() {
		logger.info("Retrieving all payments from database");
	List<Payment> allPayments = this.paymentDao.getAllPayments();
	if(allPayments != null && !allPayments.isEmpty()) {
		logger.info("Found {} payments", allPayments.size());
	return allPayments.stream()
					   .map(this::mapReviewEntityToDTO)
					   .collect(Collectors.toList());
	}

	logger.warn("No payments found in the database");
		
	return null;
}

	/**
     * Maps a Payment entity to a PaymentDTO.
     *
     * @param payment the Payment entity
     * @return the corresponding PaymentDTO
     */

	private PaymentDTO mapReviewEntityToDTO(Payment payment) {
		 
		return PaymentDTO.builder().paymentId(payment.getPaymentId()).userId(payment.getUserId())
		.bookingId(payment.getBookingId()).amount(payment.getAmount()).paymentMethod(payment.getPaymentMethod())
		.paymentStatus(payment.getStatus())
		.paymentDate(payment.getPaymentDate())
		.build();
		 
		}

}