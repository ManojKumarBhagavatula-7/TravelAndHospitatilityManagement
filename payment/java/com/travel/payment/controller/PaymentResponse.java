package com.travel.payment.controller;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.travel.payment.dto.PaymentDTO;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PaymentResponse {
	@JsonInclude(JsonInclude.Include.NON_NULL)
	private  PaymentDTO paymentRef;
	@JsonInclude(JsonInclude.Include.NON_NULL)
	private List<PaymentDTO> payments;

}
