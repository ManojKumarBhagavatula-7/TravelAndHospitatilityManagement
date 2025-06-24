package com.example.flightbooking.service.test;

import com.example.flightbooking.model.Flight;
import com.example.flightbooking.repository.FlightRepository;
import com.example.flightbooking.service.FlightServiceImpl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class FlightServiceImplTest {

    @Mock
    private FlightRepository flightRepo;

    @InjectMocks
    private FlightServiceImpl flightServiceImpl;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
    }

    // 1. Add Flight – Success
    @Test
    public void testAddFlight_Success() {
        Flight flight = new Flight();
        flight.setFlightId(1);
        flight.setDeparture("Delhi");
        flight.setArrival("Mumbai");
        flight.setAvailability(true);
        flight.setPrice(3000.0);
        flight.setCreatedAt(LocalDateTime.now());
        flight.setCreatedBy("Admin");
        flight.setUpdatedAt(LocalDateTime.now());
        flight.setUpdatedBy("Admin");

        when(flightRepo.save(any(Flight.class))).thenReturn(flight);

        Flight result = flightServiceImpl.addFlight(flight, "Admin");
        assertNotNull(result);
        assertEquals("Delhi", result.getDeparture());
    }

    // 2. Add Flight – Unauthorized User
    @Test
    public void testAddFlight_Failure_Unauthorized() {
        Flight flight = new Flight();
        Exception exception = assertThrows(RuntimeException.class, () -> flightServiceImpl.addFlight(flight, "User"));
        assertEquals("Access denied: Only Admin can manage flight details", exception.getMessage());
    }

    // 3. Update Flight – Success
    @Test
    public void testUpdateFlight_Success() {
        Flight existing = new Flight();
        existing.setFlightId(1);
        existing.setDeparture("Delhi");
        existing.setArrival("Mumbai");
        existing.setPrice(3000.0);
        existing.setAvailability(true);

        Flight updated = new Flight();
        updated.setDeparture("Delhi");
        updated.setArrival("Chennai");
        updated.setPrice(3500.0);
        updated.setAvailability(false);

        when(flightRepo.findById(1)).thenReturn(Optional.of(existing));
        when(flightRepo.save(any(Flight.class))).thenReturn(existing);

        Flight result = flightServiceImpl.updateFlight(1, updated, "Admin");
        assertEquals("Chennai", result.getArrival());
    }

    // 4. Update Flight – Not Found
    @Test
    public void testUpdateFlight_Failure_NotFound() {
        when(flightRepo.findById(1)).thenReturn(Optional.empty());

        Exception exception = assertThrows(RuntimeException.class, () ->flightServiceImpl.updateFlight(1, new Flight(), "Admin"));
        assertEquals("Flight not found", exception.getMessage());
    }

    // 5. Delete Flight – Success
    @Test
    public void testDeleteFlight_Success() {
        Flight flight = new Flight();
        flight.setFlightId(1);
        when(flightRepo.findById(1)).thenReturn(Optional.of(flight));

        flightServiceImpl.deleteFlight(1, "Admin");
        verify(flightRepo, times(1)).delete(any(Flight.class));
    }

    // 6. Delete Flight – Not Found
    @Test
    public void testDeleteFlight_Failure_NotFound() {
        when(flightRepo.findById(1)).thenReturn(Optional.empty());

        Exception exception = assertThrows(RuntimeException.class, () ->flightServiceImpl.deleteFlight(1, "Admin") );
        assertEquals("Flight not found", exception.getMessage());
    }

    // 7. Get Flight by ID – Success
    @Test
    public void testGetFlightById_Success() {
        Flight flight = new Flight();
        flight.setFlightId(1);
        when(flightRepo.findById(1)).thenReturn(Optional.of(flight));

        Flight result = flightServiceImpl.getFlight(1);
        assertNotNull(result);
        assertEquals(1, result.getFlightId());
    }

    // 8. Get Flight by ID – Not Found
    @Test
    public void testGetFlightById_Failure_NotFound() {
        when(flightRepo.findById(1)).thenReturn(Optional.empty());

        Exception exception = assertThrows(RuntimeException.class, () ->flightServiceImpl.getFlight(1));
        assertEquals("Flight not found", exception.getMessage());
    }

    // 9. Search Flights – Success
    @Test
    public void testSearchFlights_Success() {
        Flight f = new Flight();
        f.setFlightId(1);
        f.setDeparture("Delhi");
        f.setArrival("Mumbai");

        when(flightRepo.findByDepartureAndArrival("Delhi", "Mumbai"))
                .thenReturn(List.of(f));

        List<Flight> result = flightServiceImpl.searchFlights("Delhi", "Mumbai");
        assertEquals(1, result.size());
        assertEquals("Mumbai", result.get(0).getArrival());
    }

    // 10. Search Flights – Not Found
    @Test
    public void testSearchFlights_Failure_NotFound() {
        when(flightRepo.findByDepartureAndArrival("Delhi", "Pune"))
                .thenReturn(List.of());

        Exception exception = assertThrows(RuntimeException.class, () ->flightServiceImpl.searchFlights("Delhi", "Pune"));
        assertEquals("No flights found for this route", exception.getMessage());
    }
}