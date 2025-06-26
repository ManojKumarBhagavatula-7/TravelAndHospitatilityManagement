package com.travel.payment.controller;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.travel.payment.dto.PaymentDTO;
import com.travel.payment.service.PaymentServiceImpl;

import jakarta.validation.Valid;


/**
 * Controller for handling payment-related operations.
 */

@RestController
public class PaymentController {

	private static final Logger logger = LoggerFactory.getLogger(PaymentController.class);
	@Autowired
	private PaymentServiceImpl paymentServiceImpl;

/**
     * Endpoint to store a payment.
     *
     * @param paymentRequest the payment request payload
     * @return ResponseEntity containing the saved payment reference
     */
	
	@PostMapping(path = "/payments")
	public ResponseEntity<PaymentResponse> postPayment(@Valid @RequestBody PaymentRequest paymentRequest) {
		logger.info("Received payment request: {}", paymentRequest);
		PaymentDTO paymentdto = PaymentDTO.builder().userId(paymentRequest.getUserId())
				.bookingId(paymentRequest.getBookingId()).amount(paymentRequest.getAmount())
				.paymentMethod(paymentRequest.getPaymentMethod()).paymentStatus(paymentRequest.getPaymentStatus())
				.paymentDate(paymentRequest.getPaymentDate()).build();
		PaymentDTO savedPaymentDTO = this.paymentServiceImpl.storePayment(paymentdto);

		logger.info("Payment stored successfully with ID: {}", savedPaymentDTO.getPaymentId());

		return new ResponseEntity<PaymentResponse>(PaymentResponse.builder().paymentRef(savedPaymentDTO).build(),
				HttpStatus.CREATED);
	}

	/**
     * Endpoint to retrieve all payments.
     *
     * @return ResponseEntity containing the list of all payments
     */

	
	@GetMapping(path = "/payments")
	public ResponseEntity<PaymentResponse> getAllPayments() {
		logger.info("Fetching all payments");
		List<PaymentDTO> payments = this.paymentServiceImpl.getAllPayments();
		return new ResponseEntity<PaymentResponse>(PaymentResponse.builder().payments(payments).build(), HttpStatus.OK);

	}
}
