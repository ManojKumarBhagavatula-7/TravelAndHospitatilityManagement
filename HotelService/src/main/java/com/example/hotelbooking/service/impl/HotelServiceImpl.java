package com.example.hotelbooking.service.impl;

import com.example.hotelbooking.exception.CustomException;
import com.example.hotelbooking.model.Hotel;
import com.example.hotelbooking.repository.HotelRepository;
import com.example.hotelbooking.service.HotelService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class HotelServiceImpl implements HotelService {

    private static final Logger logger = LoggerFactory.getLogger(HotelServiceImpl.class);

    @Autowired
    private HotelRepository hotelRepository;

    private void ensureHotelManager(String role) {
        if (!"HotelManager".equalsIgnoreCase(role)) {
            logger.warn("Access denied: Role '{}' attempted to perform a restricted action", role);
            throw new CustomException("Access denied. Only HotelManager can perform this action.");
        }
    }

    @Override
    public Hotel registerHotel(Hotel hotel, String role) {
        logger.info("Registering hotel: {}", hotel);
        ensureHotelManager(role);
        hotel.setCreatedAt(LocalDateTime.now());
        hotel.setCreatedBy(role);
        hotel.setUpdatedAt(LocalDateTime.now());
        hotel.setUpdatedBy(role);
        Hotel savedHotel = hotelRepository.save(hotel);
        logger.info("Hotel registered successfully: {}", savedHotel);
        return savedHotel;
    }

    @Override
    public Hotel updateHotel(int hotelId, Hotel hotel, String role) {
        logger.info("Updating hotel with ID: {}", hotelId);
        ensureHotelManager(role);
        Hotel existing = hotelRepository.findById(hotelId)
            .orElseThrow(() -> {
                logger.error("Hotel not found with ID: {}", hotelId);
                return new CustomException("Hotel not found");
            });
        existing.setName(hotel.getName());
        existing.setLocation(hotel.getLocation());
        existing.setRoomsAvailable(hotel.getRoomsAvailable());
        existing.setRating(hotel.getRating());
        existing.setPricePerNight(hotel.getPricePerNight());
        existing.setUpdatedAt(LocalDateTime.now());
        existing.setUpdatedBy(role);
        Hotel updatedHotel = hotelRepository.save(existing);
        logger.info("Hotel updated successfully: {}", updatedHotel);
        return updatedHotel;
    }

    @Override
    public void deleteHotel(int hotelId, String role) {
        logger.info("Deleting hotel with ID: {}", hotelId);
        ensureHotelManager(role);
        Hotel hotel = hotelRepository.findById(hotelId)
            .orElseThrow(() -> {
                logger.error("Hotel not found with ID: {}", hotelId);
                return new CustomException("Hotel not found");
            });
        hotelRepository.delete(hotel);
        logger.info("Hotel deleted successfully with ID: {}", hotelId);
    }

    @Override
    public Hotel getHotelById(int hotelId) {
        logger.info("Fetching hotel with ID: {}", hotelId);
        return hotelRepository.findById(hotelId)
            .orElseThrow(() -> {
                logger.error("Hotel not found with ID: {}", hotelId);
                return new CustomException("Hotel not found");
            });
    }

    @Override
    public List<Hotel> searchHotels(String location) {
        logger.info("Searching hotels in location: {}", location);
        List<Hotel> results = hotelRepository.findByLocationContainingIgnoreCase(location);
        if (results.isEmpty()) {
            logger.warn("No hotels found for location: {}", location);
            throw new CustomException("No hotels found for this location");
        }
        logger.info("Hotels found for location: {}", location);
        return results;
    }
}