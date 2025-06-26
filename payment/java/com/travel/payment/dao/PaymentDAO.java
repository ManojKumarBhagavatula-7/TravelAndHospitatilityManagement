package com.travel.payment.dao;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.travel.payment.dto.PaymentDTO;
import com.travel.payment.entity.Payment;
import com.travel.payment.repository.PaymentRepository;

@Component
public class PaymentDAO {
	
	@Autowired
	private PaymentRepository paymentRepository;
	
	public PaymentDTO insertPayment(PaymentDTO paymentDto) {
	Payment paymentEntity = Payment.builder()
	.amount(paymentDto.getAmount())
	.paymentDate(paymentDto.getPaymentDate())
	.paymentMethod(paymentDto.getPaymentMethod())
	.status(paymentDto.getPaymentStatus())
	.userId(paymentDto.getUserId())
	.createdBy(paymentDto.getUserId().toString())
	.createdDate(LocalDateTime.now())
	.updatedBy(paymentDto.getUserId().toString())
	.updatedDate(LocalDateTime.now())
	.bookingId(paymentDto.getBookingId()).build();
	Payment savedPaymentEntity = this.paymentRepository.save(paymentEntity);
	return PaymentDTO.builder()
	.paymentId(savedPaymentEntity.getPaymentId())
	.amount(savedPaymentEntity.getAmount())
	.paymentDate(savedPaymentEntity.getPaymentDate())
	.paymentMethod(savedPaymentEntity.getPaymentMethod())
	.paymentStatus(savedPaymentEntity.getStatus())
	.userId(savedPaymentEntity.getUserId())
	.bookingId(savedPaymentEntity.getBookingId()).build();
	}

	public  List<Payment> getAllPayments() {
        return this.paymentRepository.findAll();
    }

}
