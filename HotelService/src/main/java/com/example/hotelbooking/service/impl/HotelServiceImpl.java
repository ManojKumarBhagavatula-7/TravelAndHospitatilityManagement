package com.example.hotelbooking.service.impl;

import com.example.hotelbooking.exception.CustomException;
import com.example.hotelbooking.model.Hotel;
import com.example.hotelbooking.repository.HotelRepository;
import com.example.hotelbooking.service.HotelService;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service

public class HotelServiceImpl implements HotelService {

    @Autowired
    private HotelRepository hotelRepository;

    private void ensureHotelManager(String role) {
        if (!"HotelManager".equalsIgnoreCase(role)) {
            throw new CustomException("Access denied. Only HotelManager can perform this action.");
        }
    }

    @Override
    public Hotel registerHotel(Hotel hotel, String role) {
        ensureHotelManager(role);
        hotel.setCreatedAt(LocalDateTime.now());
        hotel.setCreatedBy(role);
        hotel.setUpdatedAt(LocalDateTime.now());
        hotel.setUpdatedBy(role);
        return hotelRepository.save(hotel);
    }

    @Override
    public Hotel updateHotel(int hotelId, Hotel hotel, String role) {
        ensureHotelManager(role);
        Hotel existing = hotelRepository.findById(hotelId)
            .orElseThrow(() -> new CustomException("Hotel not found"));
        existing.setName(hotel.getName());
        existing.setLocation(hotel.getLocation());
        existing.setRoomsAvailable(hotel.getRoomsAvailable());
        existing.setRating(hotel.getRating());
        existing.setPricePerNight(hotel.getPricePerNight());
        existing.setUpdatedAt(LocalDateTime.now());
        existing.setUpdatedBy(role);
        
        
        return hotelRepository.save(existing);
    }

    @Override
    public void deleteHotel(int hotelId, String role) {
        ensureHotelManager(role);
        Hotel hotel = hotelRepository.findById(hotelId)
            .orElseThrow(() -> new CustomException("Hotel not found"));
        hotelRepository.delete(hotel);
    }

    @Override
    public Hotel getHotelById(int hotelId) {
        return hotelRepository.findById(hotelId)
            .orElseThrow(() -> new CustomException("Hotel not found"));
    }

    @Override
    public List<Hotel> searchHotels(String location) {
        List<Hotel> results = hotelRepository.findByLocationContainingIgnoreCase(location);
        if (results.isEmpty()) {
            throw new CustomException("No hotels found in this location");
        }
        return results;
    }
}