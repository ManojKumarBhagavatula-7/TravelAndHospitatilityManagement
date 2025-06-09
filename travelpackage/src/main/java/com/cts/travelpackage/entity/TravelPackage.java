package com.cts.travelpackage.entity;

import java.math.BigDecimal;
import java.util.List;

import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import com.cts.travelpackage.entity.base.Auditable;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
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
@Table(name = "package")
@EnableJpaAuditing
public class TravelPackage extends Auditable<String>{
	
	@Id
	@Column(name="packageId")
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long packageId;
	
	@Column(name="packageName")
	private String packageName;
	
	@ElementCollection
	private List<Long> includedHotelIds;

	@ElementCollection
	private List<Long> includedFlightIds;
	
	@ElementCollection
	private List<String> activities;
	
	private BigDecimal price;
	

	@OneToMany(mappedBy = "travelPackage", cascade = CascadeType.ALL)
	private List<Itinerary> itineraries;

	
}
