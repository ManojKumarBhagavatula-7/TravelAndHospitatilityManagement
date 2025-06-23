package com.cts.booking.repository;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.cts.booking.entity.Booking;

@Repository
public interface BookingRepository extends JpaRepository<Booking,Long>{
	
	Page<Booking> findByUserId(Long userId, Pageable pageable);
  
   
    Page<Booking> findByTypeIgnoreCase(String type, Pageable pageable);
    Page<Booking> findByStatusIgnoreCase(String status, Pageable pageable);
    Page<Booking> findByStatusIgnoreCaseIn(List<String> statuses, Pageable pageable);

}


