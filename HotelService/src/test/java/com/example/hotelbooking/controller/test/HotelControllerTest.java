package com.example.hotelbooking.controller.test;

import com.example.hotelbooking.controller.HotelController;
import com.example.hotelbooking.model.Hotel;
import com.example.hotelbooking.service.HotelService;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class HotelControllerTest {

    @Mock
    private HotelService hotelService;

    @InjectMocks
    private HotelController hotelController;

    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
    }

    // 1. Add Hotel – Success
    @Test
    void testAddHotel_Success() {
        Hotel hotel = new Hotel();
        hotel.setName("Taj");
        when(hotelService.registerHotel(any(Hotel.class), eq("HotelManager"))).thenReturn(hotel);

        Hotel result = hotelController.registerHotel(hotel, "HotelManager");
        assertNotNull(result);
        assertEquals("Taj", result.getName());
    }

    // 2. Add Hotel – Unauthorized
    
    @Test
    public void testAddHotel_Failure_Unauthorized() {
        Hotel hotel = new Hotel();

        when(hotelService.registerHotel(any(Hotel.class), eq("User")))
            .thenThrow(new RuntimeException("Access denied: Only HotelManager can manage hotel details"));

        Exception exception = assertThrows(RuntimeException.class, () ->hotelController.registerHotel(hotel, "User"));

        assertEquals("Access denied: Only HotelManager can manage hotel details", exception.getMessage());
    }

    // 3. Update Hotel – Success
    @Test
    void testUpdateHotel_Success() {
        Hotel hotel = new Hotel();
        hotel.setName("Taj Deluxe");
        when(hotelService.updateHotel(eq(1), any(Hotel.class), eq("HotelManager"))).thenReturn(hotel);

        Hotel result = hotelController.updateHotel(1, hotel, "HotelManager");
        assertEquals("Taj Deluxe", result.getName());
    }

    // 4. Update Hotel – Not Found
    @Test
    void testUpdateHotel_Failure_NotFound() {
        Hotel hotel = new Hotel();
        when(hotelService.updateHotel(eq(1), any(Hotel.class), eq("HotelManager")))
                .thenThrow(new RuntimeException("Hotel not found"));

        Exception ex = assertThrows(RuntimeException.class,() -> hotelController.updateHotel(1, hotel, "HotelManager"));
        assertEquals("Hotel not found", ex.getMessage());
    }

    // 5. Delete Hotel – Success
    @Test
    void testDeleteHotel_Success() {
        doNothing().when(hotelService).deleteHotel(1, "HotelManager");
        hotelController.deleteHotel(1, "HotelManager");
        verify(hotelService, times(1)).deleteHotel(1, "HotelManager");
    }

    // 6. Delete Hotel – Not Found
    @Test
    void testDeleteHotel_Failure_NotFound() {
        doThrow(new RuntimeException("Hotel not found"))
                .when(hotelService).deleteHotel(1, "HotelManager");

        Exception ex = assertThrows(RuntimeException.class,
                () -> hotelController.deleteHotel(1, "HotelManager"));
        assertEquals("Hotel not found", ex.getMessage());
    }

    // 7. Get Hotel by ID – Success
    @Test
    void testGetHotelById_Success() {
        Hotel hotel = new Hotel();
        hotel.setHotelId(1);
        when(hotelService.getHotelById(1)).thenReturn(hotel);

        Hotel result = hotelController.getHotel(1);
        assertEquals(1, result.getHotelId());
    }

    // 8. Get Hotel by ID – Not Found
    @Test
    void testGetHotelById_Failure_NotFound() {
        when(hotelService.getHotelById(1)).thenThrow(new RuntimeException("Hotel not found"));

        Exception ex = assertThrows(RuntimeException.class,
                () -> hotelController.getHotel(1));
        assertEquals("Hotel not found", ex.getMessage());
    }

    // 9. Search Hotels – Success
    @Test
    void testSearchHotels_Success() {
        Hotel hotel = new Hotel();
        hotel.setLocation("Goa");
        when(hotelService.searchHotels("Goa")).thenReturn(List.of(hotel));

        List<Hotel> result = hotelController.searchHotels("Goa");
        assertEquals(1, result.size());
        assertEquals("Goa", result.get(0).getLocation());
    }

    // 10. Search Hotels – Not Found
    @Test
    void testSearchHotels_Failure_NotFound() {
        when(hotelService.searchHotels("Delhi")).thenThrow(new RuntimeException("No hotels found for this location"));

        Exception ex = assertThrows(RuntimeException.class,
                () -> hotelController.searchHotels("Delhi"));
        assertEquals("No hotels found for this location", ex.getMessage());
    }
}