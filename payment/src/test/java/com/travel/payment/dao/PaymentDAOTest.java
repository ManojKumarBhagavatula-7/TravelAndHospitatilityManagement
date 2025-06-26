package com.travel.payment.dao;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.travel.payment.dto.PaymentDTO;
import com.travel.payment.entity.Payment;
import com.travel.payment.repository.PaymentRepository;

@ExtendWith(MockitoExtension.class)
public class PaymentDAOTest {

    @InjectMocks
    private PaymentDAO paymentDAO;

    @Mock
    private PaymentRepository paymentRepository;

    @Test
    public void testInsertPayment() {
        PaymentDTO dto = PaymentDTO.builder()
                .amount(new BigDecimal("100.00"))
                .paymentDate(LocalDateTime.now())
                .paymentMethod("Credit Card")
                .paymentStatus("Success")
                .userId(1)
                .bookingId(101)
                .build();

        Payment entity = Payment.builder()
                .paymentId(1)
                .amount(dto.getAmount())
                .paymentDate(dto.getPaymentDate())
                .paymentMethod(dto.getPaymentMethod())
                .status(dto.getPaymentStatus())
                .userId(dto.getUserId())
                .bookingId(dto.getBookingId())
                .createdBy("1")
                .createdDate(LocalDateTime.now())
                .updatedBy("1")
                .updatedDate(LocalDateTime.now())
                .build();

        when(paymentRepository.save(any(Payment.class))).thenReturn(entity);

        PaymentDTO result = paymentDAO.insertPayment(dto);

        assertNotNull(result);
        assertEquals(dto.getAmount(), result.getAmount());
        assertEquals(dto.getUserId(), result.getUserId());
        assertEquals(dto.getBookingId(), result.getBookingId());
    }

    @Test
    public void testGetAllPayments() {
        List<Payment> payments = List.of(
                Payment.builder().paymentId(1).amount(new BigDecimal("100.00")).build(),
                Payment.builder().paymentId(2).amount(new BigDecimal("200.00")).build()
        );

        when(paymentRepository.findAll()).thenReturn(payments);

        List<Payment> result = paymentDAO.getAllPayments();

        assertEquals(2, result.size());
        assertEquals(new BigDecimal("100.00"), result.get(0).getAmount());
        assertEquals(new BigDecimal("200.00"), result.get(1).getAmount());
    }
}
