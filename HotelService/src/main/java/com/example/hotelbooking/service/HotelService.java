package com.example.hotelbooking.service;

import com.example.hotelbooking.model.Hotel;

import java.util.List;

public interface HotelService {
    Hotel registerHotel(Hotel hotel, String role);
    Hotel updateHotel(int hotelId, Hotel hotel, String role);
    void deleteHotel(int hotelId, String role);
    Hotel getHotelById(int hotelId);
    List<Hotel> searchHotels(String location);
}