package com.travel.payment.entity;

import java.math.BigDecimal;
import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "Payment")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Payment {

	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer paymentId;
 
    private Integer userId;
    
    @Column(nullable = false, unique = true)
    private Integer bookingId;

 
    @Column(nullable = false)
    private BigDecimal amount;
 
    @Column(nullable = false)
    private String status; // Should be one of: Pending, Completed, Failed
 
    @Column(nullable = false)
    private String paymentMethod;
 
    @Column(nullable = false)
private LocalDateTime paymentDate = LocalDateTime.now();
private LocalDateTime createdDate = LocalDateTime.now();
 
    private String createdBy;
 
private LocalDateTime updatedDate = LocalDateTime.now();
 
    private String updatedBy;
}
