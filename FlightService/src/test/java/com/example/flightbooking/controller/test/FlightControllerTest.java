package com.example.flightbooking.controller.test;

import com.example.flightbooking.controller.FlightController;
import com.example.flightbooking.model.Flight;
import com.example.flightbooking.service.FlightService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;


import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class FlightControllerTest {

    @Mock
    private FlightService flightService;

    @InjectMocks
    private FlightController flightController;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
    }

    // --- ADD FLIGHT ---
    @Test
    public void testAddFlight_Success() {
        Flight flight = new Flight();
        flight.setFlightId(1);
        flight.setDeparture("Delhi");

        when(flightService.addFlight(any(Flight.class), eq("Admin"))).thenReturn(flight);

        Flight result = flightController.addFlight(flight, "Admin");
        assertNotNull(result);
        assertEquals("Delhi", result.getDeparture());
    }

    @Test
    public void testAddFlight_Failure_UnauthorizedUser() {
        Flight flight = new Flight();

        // tell mock to throw the exception
        when(flightService.addFlight(flight, "User"))
            .thenThrow(new RuntimeException("Access denied: Only Admin can manage flight details"));

        Exception exception = assertThrows(RuntimeException.class, () ->flightController.addFlight(flight, "User"));

        assertEquals("Access denied: Only Admin can manage flight details", exception.getMessage());
    }

    // --- UPDATE FLIGHT ---
    @Test
    public void testUpdateFlight_Success() {
        Flight flight = new Flight();
        flight.setArrival("Chennai");

        when(flightService.updateFlight(eq(1), any(Flight.class), eq("Admin"))).thenReturn(flight);

        Flight result = flightController.updateFlight(1, flight, "Admin");
        assertEquals("Chennai", result.getArrival());
    }

    @Test
    public void testUpdateFlight_Failure_NotFound() {
        when(flightService.updateFlight(eq(1), any(Flight.class), eq("Admin")))
                .thenThrow(new RuntimeException("Flight not found"));

        Exception exception = assertThrows(RuntimeException.class, () ->flightController.updateFlight(1, new Flight(), "Admin"));
        assertEquals("Flight not found", exception.getMessage());
    }

    // --- DELETE FLIGHT ---
    @Test
    public void testDeleteFlight_Success() {
        doNothing().when(flightService).deleteFlight(1, "Admin");

        assertDoesNotThrow(() -> flightController.deleteFlight(1, "Admin"));
        verify(flightService, times(1)).deleteFlight(1, "Admin");
    }

    @Test
    public void testDeleteFlight_Failure_NotFound() {
        doThrow(new RuntimeException("Flight not found"))
                .when(flightService).deleteFlight(1, "Admin");

        Exception exception = assertThrows(RuntimeException.class, () -> flightController.deleteFlight(1, "Admin"));
        assertEquals("Flight not found", exception.getMessage());
    }

    // --- GET BY ID ---
    @Test
    public void testGetFlightById_Success() {
        Flight flight = new Flight();
        flight.setFlightId(1);

        when(flightService.getFlight(1)).thenReturn(flight);

        Flight result = flightController.getFlight(1);
        assertNotNull(result);
        assertEquals(1, result.getFlightId());
    }

    @Test
    public void testGetFlightById_Failure_NotFound() {
        when(flightService.getFlight(1)).thenThrow(new RuntimeException("Flight not found"));

        Exception exception = assertThrows(RuntimeException.class, () ->flightController.getFlight(1));
        assertEquals("Flight not found", exception.getMessage());
    }

    // --- SEARCH FLIGHTS ---
    @Test
    public void testSearchFlightsByLocation_Success() {
        Flight flight = new Flight();
        flight.setArrival("Mumbai");

        when(flightService.searchFlights("Delhi", "Mumbai")).thenReturn(List.of(flight));

        List<Flight> results = flightController.search("Delhi", "Mumbai");
        assertEquals(1, results.size());
        assertEquals("Mumbai", results.get(0).getArrival());
    }

    @Test
    public void testSearchFlightsByLocation_Failure_NotFound() {
        when(flightService.searchFlights("Delhi", "Chandigarh")).thenThrow(new RuntimeException("No flights found"));

        Exception exception = assertThrows(RuntimeException.class, () ->flightController.search("Delhi", "Chandigarh"));
        assertEquals("No flights found", exception.getMessage());
    }
}