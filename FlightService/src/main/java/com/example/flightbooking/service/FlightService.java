package com.example.flightbooking.service;

import com.example.flightbooking.model.Flight;

import java.util.List;

public interface FlightService {

    public Flight addFlight(Flight flight, String createdByRole);

    public Flight updateFlight(int id, Flight updated, String updaterRole);

    public void deleteFlight(int id, String role);

    public Flight getFlight(int id);

    public List<Flight> searchFlights(String departure, String arrival);
}
