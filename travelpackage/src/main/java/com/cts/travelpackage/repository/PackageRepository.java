package com.cts.travelpackage.repository;



import org.springframework.data.jpa.repository.JpaRepository;

import org.springframework.stereotype.Repository;

import com.cts.travelpackage.entity.TravelPackage;

@Repository
public interface PackageRepository extends JpaRepository<TravelPackage,Long>{


}
