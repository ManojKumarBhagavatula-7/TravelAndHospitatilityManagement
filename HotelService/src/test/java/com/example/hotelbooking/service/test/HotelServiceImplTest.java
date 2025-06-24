package com.example.hotelbooking.service.test;


import com.example.hotelbooking.model.Hotel;
import com.example.hotelbooking.repository.HotelRepository;
import com.example.hotelbooking.service.impl.HotelServiceImpl;

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

class HotelServiceImplTest {

    @Mock
    private HotelRepository hotelRepo;

    @InjectMocks
    private HotelServiceImpl hotelServiceImpl;

    @BeforeEach
    public void setup() {
        MockitoAnnotations.openMocks(this);
    }

    // 1. Add Hotel – Success
    @Test
    public void testAddHotel_Success() {
        Hotel hotel = new Hotel(1, "Taj", "Mumbai", 30, 4.8, 8000.0,
                LocalDateTime.now(), "Manager", LocalDateTime.now(), "Manager");

        when(hotelRepo.save(any(Hotel.class))).thenReturn(hotel);

        Hotel result = hotelServiceImpl.registerHotel(hotel, "HotelManager");
        assertNotNull(result);
        assertEquals("Taj", result.getName());
    }

    // 2. Add Hotel – Unauthorized
    @Test
    public void testAddHotel_Failure_Unauthorized() {
        Hotel hotel = new Hotel();
        Exception exception = assertThrows(RuntimeException.class, () ->hotelServiceImpl.registerHotel(hotel, "User"));
        assertEquals("Access denied. Only HotelManager can perform this action.", exception.getMessage());
    }
    
    

    // 3. Update Hotel – Success
    @Test
    public void testUpdateHotel_Success() {
        Hotel existing = new Hotel(1, "Taj", "Mumbai", 30, 4.8, 8000.0,
                LocalDateTime.now(), "Manager", LocalDateTime.now(), "Manager");

        Hotel updated = new Hotel(1, "Taj Luxury", "Mumbai", 25, 5.0, 9000.0,
                null, null, null, null);

        when(hotelRepo.findById(1)).thenReturn(Optional.of(existing));
        when(hotelRepo.save(any(Hotel.class))).thenReturn(existing);

        Hotel result = hotelServiceImpl.updateHotel(1, updated, "HotelManager");
        assertEquals("Taj Luxury", result.getName());
    }

    // 4. Update Hotel – Not Found
    @Test
    public void testUpdateHotel_Failure_NotFound() {
        when(hotelRepo.findById(1)).thenReturn(Optional.empty());

        Exception exception = assertThrows(RuntimeException.class, () ->hotelServiceImpl.updateHotel(1, new Hotel(), "HotelManager"));
        assertEquals("Hotel not found", exception.getMessage());
    }

    // 5. Delete Hotel – Success
    @Test
    public void testDeleteHotel_Success() {
        Hotel hotel = new Hotel();
        when(hotelRepo.findById(1)).thenReturn(Optional.of(hotel));
        hotelServiceImpl.deleteHotel(1, "HotelManager");
        verify(hotelRepo, times(1)).delete(hotel);
    }

    // 6. Delete Hotel – Not Found
    @Test
    public void testDeleteHotel_Failure_NotFound() {
        when(hotelRepo.findById(1)).thenReturn(Optional.empty());
        Exception exception = assertThrows(RuntimeException.class, () -> hotelServiceImpl.deleteHotel(1, "HotelManager"));
        assertEquals("Hotel not found", exception.getMessage());
    }

    // 7. Get Hotel by ID – Success
    @Test
    public void testGetHotelById_Success() {
        Hotel hotel = new Hotel();
        hotel.setHotelId(1);
        when(hotelRepo.findById(1)).thenReturn(Optional.of(hotel));

        Hotel result = hotelServiceImpl.getHotelById(1);
        assertEquals(1, result.getHotelId());
    }

    // 8. Get Hotel by ID – Not Found
    @Test
    public void testGetHotelById_Failure_NotFound() {
        when(hotelRepo.findById(1)).thenReturn(Optional.empty());
        Exception exception = assertThrows(RuntimeException.class, () ->hotelServiceImpl.getHotelById(1));
        assertEquals("Hotel not found", exception.getMessage());
    }

    // 9. Search Hotels – Success
    @Test
    public void testSearchHotels_Success() {
        Hotel h = new Hotel(1, "Taj", "Mumbai", 30, 4.8, 8000.0,
                LocalDateTime.now(), "Manager", LocalDateTime.now(), "Manager");

        when(hotelRepo.findByLocationContainingIgnoreCase("Mumbai")).thenReturn(List.of(h));

        List<Hotel> result = hotelServiceImpl.searchHotels("Mumbai");
        assertEquals(1, result.size());
        assertEquals("Mumbai", result.get(0).getLocation());
    }

    // 10. Search Hotels – Not Found
    @Test
    public void testSearchHotels_Failure_NotFound() {
        when(hotelRepo.findByLocationContainingIgnoreCase("Pune")).thenReturn(List.of());

        Exception exception = assertThrows(RuntimeException.class, () ->hotelServiceImpl.searchHotels("Pune"));
        assertEquals("No hotels found for this location", exception.getMessage());
    }
}