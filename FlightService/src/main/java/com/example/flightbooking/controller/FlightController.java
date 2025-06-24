package com.example.flightbooking.controller;

import com.example.flightbooking.model.Flight;
import com.example.flightbooking.service.FlightService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

@RestController
@RequestMapping("/api/flights")
public class FlightController {

    private static final Logger logger = LoggerFactory.getLogger(FlightController.class);

    @Autowired
    private FlightService service;

    @Operation(summary = "Add a new flight", description = "Only Admin can add a new flight")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Flight added successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid input"),
        @ApiResponse(responseCode = "403", description = "Access denied (only Admin)"),
        @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PostMapping
    public Flight addFlight(@RequestBody Flight flight, @RequestParam String role) {
        logger.info("Adding flight: {}", flight);
        return service.addFlight(flight, role);
    }

    @Operation(summary = "Update flight", description = "Only Admin can update flight")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Flight updated successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid input"),
        @ApiResponse(responseCode = "403", description = "Access denied (only Admin)"),
        @ApiResponse(responseCode = "404", description = "Flight not found"),
        @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PutMapping("/{id}")
    public Flight updateFlight(@PathVariable int id, @RequestBody Flight flight, @RequestParam String role) {
        logger.info("Updating flight with ID: {}", id);
        return service.updateFlight(id, flight, role);
    }

    @Operation(summary = "Delete flight", description = "Only Admin can delete a flight")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Flight deleted successfully"),
        @ApiResponse(responseCode = "403", description = "Access denied (only Admin)"),
        @ApiResponse(responseCode = "404", description = "Flight not found"),
        @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @DeleteMapping("/{id}")
    public void deleteFlight(@PathVariable int id, @RequestParam String role) {
        logger.info("Deleting flight with ID: {}", id);
        service.deleteFlight(id, role);
    }

    @Operation(summary = "Get flight by ID", description = "Fetch flight details using flight ID")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Flight fetched successfully"),
        @ApiResponse(responseCode = "404", description = "Flight not found"),
        @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @GetMapping("/{id}")
    public Flight getFlight(@PathVariable int id) {
        logger.info("Fetching flight with ID: {}", id);
        return service.getFlight(id);
    }

    @Operation(summary = "Search flights", description = "Search flights by departure and arrival")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Flights found successfully"),
        @ApiResponse(responseCode = "400", description = "Missing or invalid query parameters"),
        @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @GetMapping("/search")
    public List<Flight> search(@RequestParam String departure, @RequestParam String arrival) {
        logger.info("Searching flights from '{}' to '{}'", departure, arrival);
        return service.searchFlights(departure, arrival);
    }
}