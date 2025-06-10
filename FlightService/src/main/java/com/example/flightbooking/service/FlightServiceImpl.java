package com.example.flightbooking.service;

import com.example.flightbooking.model.Flight;
import com.example.flightbooking.repository.FlightRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class FlightServiceImpl implements FlightService {

    @Autowired
    private FlightRepository flightRepo;

    private void ensureAdmin(String role) {
        if (!"Admin".equalsIgnoreCase(role)) {
            throw new RuntimeException("Access denied: Only Admin can manage flight details");
        }
    }
    
    @Override
    public Flight addFlight(Flight flight, String createdByRole) {
        ensureAdmin(createdByRole);
        flight.setCreatedAt(LocalDateTime.now());
        flight.setCreatedBy(createdByRole);
        flight.setUpdatedAt(LocalDateTime.now());
        flight.setUpdatedBy(createdByRole);
        return flightRepo.save(flight);
    }

    @Override
    public Flight updateFlight(int id, Flight updated, String updaterRole) {
        ensureAdmin(updaterRole);
        Flight f = flightRepo.findById(id).orElseThrow();
        f.setAirline(updated.getAirline());
        f.setDeparture(updated.getDeparture());
        f.setArrival(updated.getArrival());
        f.setDepartureTime(updated.getDepartureTime());
        f.setArrivalTime(updated.getArrivalTime());
        f.setPrice(updated.getPrice());
        f.setAvailability(updated.isAvailability());
        f.setUpdatedAt(LocalDateTime.now());
        f.setUpdatedBy(updaterRole);
        return flightRepo.save(f);
    }
    
    @Override
    public void deleteFlight(int id, String role) {
        ensureAdmin(role);
        flightRepo.deleteById(id);
    }

    @Override
    public Flight getFlight(int id) {
        return flightRepo.findById(id).orElseThrow();
    }
    
    @Override
    public List<Flight> searchFlights(String departure, String arrival) {
        return flightRepo.findByDepartureAndArrival(departure, arrival);
    }
}
