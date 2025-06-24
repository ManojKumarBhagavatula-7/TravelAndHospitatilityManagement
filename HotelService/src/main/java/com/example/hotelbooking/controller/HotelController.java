package com.example.hotelbooking.controller;

import com.example.hotelbooking.model.Hotel;
import com.example.hotelbooking.service.HotelService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

@RestController
@RequestMapping("/api/hotels")
public class HotelController {

    private static final Logger logger = LoggerFactory.getLogger(HotelController.class);

    @Autowired
    private HotelService hotelService;

    @Operation(summary = "Register a new hotel", description = "Accessible only by HotelManager")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Hotel registered successfully"),
            @ApiResponse(responseCode = "403", description = "Access denied. Only HotelManager can perform this action."),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping
    public Hotel registerHotel(@RequestBody Hotel hotel,
                               @RequestParam @Parameter(description = "Role should be 'HotelManager'") String role) {
        logger.info("Registering hotel: {}", hotel);
        return hotelService.registerHotel(hotel, role);
    }

    @Operation(summary = "Update hotel profile", description = "Accessible only by HotelManager")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Hotel updated successfully"),
            @ApiResponse(responseCode = "404", description = "Hotel not found"),
            @ApiResponse(responseCode = "403", description = "Access denied. Only HotelManager can perform this action."),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PutMapping("/{hotelId}")
    public Hotel updateHotel(@PathVariable int hotelId,
                             @RequestBody Hotel hotel,
                             @RequestParam @Parameter(description = "Role should be 'HotelManager'") String role) {
        logger.info("Updating hotel with ID: {}", hotelId);
        return hotelService.updateHotel(hotelId, hotel, role);
    }

    @Operation(summary = "Delete a hotel", description = "Accessible only by HotelManager")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Hotel deleted successfully"),
            @ApiResponse(responseCode = "404", description = "Hotel not found"),
            @ApiResponse(responseCode = "403", description = "Access denied. Only HotelManager can perform this action.")
    })
    @DeleteMapping("/{hotelId}")
    public void deleteHotel(@PathVariable int hotelId,
                            @RequestParam @Parameter(description = "Role should be 'HotelManager'") String role) {
        logger.info("Deleting hotel with ID: {}", hotelId);
        hotelService.deleteHotel(hotelId, role);
    }

    @Operation(summary = "Get hotel profile", description = "Fetch hotel by ID")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Hotel profile fetched"),
            @ApiResponse(responseCode = "404", description = "Hotel not found")
    })
    @GetMapping("/{hotelId}")
    public Hotel getHotel(@PathVariable int hotelId) {
        logger.info("Fetching hotel with ID: {}", hotelId);
        return hotelService.getHotelById(hotelId);
    }

    @Operation(summary = "Search hotels by location")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Matching hotels returned"),
            @ApiResponse(responseCode = "404", description = "No hotels found")
    })
    @GetMapping("/search")
    public List<Hotel> searchHotels(@RequestParam String location) {
        logger.info("Searching hotels in location: {}", location);
        return hotelService.searchHotels(location);
    }
}