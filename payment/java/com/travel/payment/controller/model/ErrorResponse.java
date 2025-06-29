package com.travel.payment.controller.model;

import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ErrorResponse {
	
	 private int status;
	    private String message;
	    private LocalDateTime timestamp;

}
