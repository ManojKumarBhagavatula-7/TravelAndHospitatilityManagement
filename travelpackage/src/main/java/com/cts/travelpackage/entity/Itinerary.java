package com.cts.travelpackage.entity;

import java.math.BigDecimal;

import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import com.cts.travelpackage.entity.base.Auditable;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;


@Entity
@Data
@EqualsAndHashCode(callSuper = false)
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "itinerary")
@EnableJpaAuditing

public class Itinerary extends Auditable<String>{
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name="itineraryId")
	private Long itineraryId;
	
	@Column(name="userId")
	private Long userId;
	
	@Column(name="customizationDetails")
	private String customizationDetails;
	
	@Column(name="price")
	private BigDecimal price;


	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "packageId")
	private TravelPackage travelPackage;



}
