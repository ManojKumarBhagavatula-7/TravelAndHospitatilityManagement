package com.travel.payment.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.travel.payment.dto.PaymentDTO;
import com.travel.payment.service.PaymentServiceImpl;
	 
	@WebMvcTest(PaymentController.class)
	public class PaymentControllerTest {
	 
	    @Autowired
	    private MockMvc mockMvc;
	 
	    @MockBean
	    private PaymentServiceImpl paymentServiceImpl;
	 
	    @Autowired
	    private ObjectMapper objectMapper;
	 
	    @Test
	    void testPostPayment_Success() throws Exception {
	        PaymentRequest request = PaymentRequest.builder()
	                .userId(1)
	                .bookingId(2)
	                .amount(new BigDecimal("150.00"))
	                .paymentMethod("CreditCard")
	                .paymentStatus("Completed")
	                .paymentDate(LocalDateTime.now())
	                .build();
	 
	        PaymentDTO savedDTO = PaymentDTO.builder()
	                .paymentId(100)
	                .userId(1)
	                .bookingId(2)
	                .amount(new BigDecimal("150.00"))
	                .paymentMethod("CreditCard")
	                .paymentStatus("Completed")
	                .paymentDate(request.getPaymentDate())
	                .build();
	 
	        Mockito.when(paymentServiceImpl.storePayment(any(PaymentDTO.class))).thenReturn(savedDTO);
	 
	        mockMvc.perform(post("/payments")
	                        .contentType(MediaType.APPLICATION_JSON)
	                        .content(objectMapper.writeValueAsString(request)))
	                .andExpect(status().isCreated())
	                .andExpect(jsonPath("$.paymentRef.paymentId").value(100));
	    }
	 

	 
	    @Test
	    void testPostPayment_InternalServerError() throws Exception {
	        PaymentRequest request = PaymentRequest.builder()
	                .userId(1)
	                .bookingId(2)
	                .amount(new BigDecimal("150.00"))
	                .paymentMethod("CreditCard")
	                .paymentStatus("Completed")
	                .paymentDate(LocalDateTime.now())
	                .build();
	 
	        Mockito.when(paymentServiceImpl.storePayment(any(PaymentDTO.class)))
	                .thenThrow(new RuntimeException("Database error"));
	 
	        mockMvc.perform(post("/payments")
	                        .contentType(MediaType.APPLICATION_JSON)
	                        .content(objectMapper.writeValueAsString(request)))
	                .andExpect(status().isInternalServerError());
	    }
	 
	    @Test
	    void testGetAllPayments_Success() throws Exception {
	        PaymentDTO dto = PaymentDTO.builder()
	                .paymentId(100)
	                .userId(1)
	                .bookingId(2)
	                .amount(new BigDecimal("150.00"))
	                .paymentMethod("CreditCard")
	                .paymentStatus("Completed")
	                .paymentDate(LocalDateTime.now())
	                .build();
	 
	        Mockito.when(paymentServiceImpl.getAllPayments()).thenReturn(List.of(dto));
	 
	        mockMvc.perform(get("/payments"))
	                .andExpect(status().isOk())
	                .andExpect(jsonPath("$.payments[0].paymentId").value(100));
	    }
	 
	    @Test
	    void testGetAllPayments_Exception() throws Exception {
	        Mockito.when(paymentServiceImpl.getAllPayments())
	                .thenThrow(new RuntimeException("DB down"));
	 
	        mockMvc.perform(get("/payments"))
	                .andExpect(status().isInternalServerError());
	    }
	}
	 