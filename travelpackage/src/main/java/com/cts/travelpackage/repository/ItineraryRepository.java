package com.cts.travelpackage.repository;

import java.util.List;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.cts.travelpackage.dto.TopSellingPackageDto;
import com.cts.travelpackage.entity.Itinerary;

@Repository
public interface ItineraryRepository extends JpaRepository<Itinerary,Long>{

	

	@Query("SELECT p.packageId, p.packageName, p.price, COUNT(i)  " +
		       "FROM Itinerary i JOIN i.travelPackage p " +
		       "GROUP BY p.packageId, p.packageName, p.price " +
		       "ORDER BY COUNT(i) DESC")
		List<TopSellingPackageDto> findTopSellingPackagesWithDetails(Pageable pageable);

}



