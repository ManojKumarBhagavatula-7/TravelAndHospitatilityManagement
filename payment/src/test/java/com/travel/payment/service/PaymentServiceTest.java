package com.travel.payment.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.travel.payment.dao.PaymentDAO;
import com.travel.payment.dto.PaymentDTO;
import com.travel.payment.entity.Payment;
import com.travel.payment.exceptions.DuplicatePaymentException;
import com.travel.payment.repository.PaymentRepository;

@ExtendWith(MockitoExtension.class)
public class PaymentServiceTest {

    @Mock
    private PaymentDAO paymentDAO;

    @Mock
    private PaymentRepository paymentRepository;

    @InjectMocks
    private PaymentServiceImpl paymentService;

    @Test
    public void testStorePaymentSuccess() {
        PaymentDTO dto = PaymentDTO.builder()
                .userId(1)
                .bookingId(101)
                .amount(new BigDecimal("100.00"))
                .paymentMethod("Credit Card")
                .paymentStatus("Success")
                .paymentDate(LocalDateTime.now())
                .build();

        when(paymentRepository.findByBookingId(dto.getBookingId())).thenReturn(Optional.empty());
        when(paymentDAO.insertPayment(dto)).thenReturn(dto);

        PaymentDTO result = paymentService.storePayment(dto);

        assertNotNull(result);
        assertEquals(dto.getBookingId(), result.getBookingId());
        assertEquals(dto.getAmount(), result.getAmount());
        assertEquals(dto.getPaymentMethod(), result.getPaymentMethod());
        assertEquals(dto.getPaymentStatus(), result.getPaymentStatus());
    }

    @Test
    public void testStorePaymentDuplicate() {
        PaymentDTO dto = PaymentDTO.builder()
                .userId(1)
                .bookingId(101)
                .amount(new BigDecimal("100.00"))
                .paymentMethod("Credit Card")
                .paymentStatus("Success")
                .paymentDate(LocalDateTime.now())
                .build();

        Payment existingPayment = Payment.builder()
                .paymentId(1)
                .bookingId(101)
                .build();

        when(paymentRepository.findByBookingId(dto.getBookingId())).thenReturn(Optional.of(existingPayment));

        DuplicatePaymentException exception = assertThrows(DuplicatePaymentException.class, () -> {
            paymentService.storePayment(dto);
        });

        assertEquals("Payment already exists with this booking ID : 101", exception.getMessage());
    }

    @Test
    public void testGetAllPaymentsSuccess() {
        List<Payment> payments = List.of(
                Payment.builder().paymentId(1).userId(1).bookingId(101).amount(new BigDecimal("100.00")).build(),
                Payment.builder().paymentId(2).userId(2).bookingId(102).amount(new BigDecimal("200.00")).build()
        );

        when(paymentDAO.getAllPayments()).thenReturn(payments);

        List<PaymentDTO> result = paymentService.getAllPayments();

        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals(101, result.get(0).getBookingId());
    }

    @Test
    public void testGetAllPaymentsEmpty() {
        when(paymentDAO.getAllPayments()).thenReturn(List.of());

        List<PaymentDTO> result = paymentService.getAllPayments();

        assertNull(result);
    }

    @Test
    public void testStorePaymentUnexpectedException() {
        PaymentDTO dto = PaymentDTO.builder()
                .userId(1)
                .bookingId(101)
                .amount(new BigDecimal("100.00"))
                .paymentMethod("Credit Card")
                .paymentStatus("Success")
                .paymentDate(LocalDateTime.now())
                .build();

        when(paymentRepository.findByBookingId(dto.getBookingId())).thenThrow(new RuntimeException("DB error"));

        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            paymentService.storePayment(dto);
        });

        assertEquals("DB error", exception.getMessage());
    }
}
