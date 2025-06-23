package com.cts.booking.controller;
 
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.cts.booking.config.TestSecurityConfig;
import com.cts.booking.dto.BookingDto;
import com.cts.booking.dto.BookingResponseDto;
import com.cts.booking.exception.ResourceNotFoundException;
import com.cts.booking.service.BookingService;
import com.fasterxml.jackson.databind.ObjectMapper;
 
@WebMvcTest(BookingController.class)
@Import(TestSecurityConfig.class)
class BookingControllerTest {
 
    @Autowired
    private MockMvc mockMvc;
 
    @MockBean
    private BookingService bookingService;
 
    @Autowired
    private ObjectMapper objectMapper;
 
    private BookingDto bookingDto;
 
    @BeforeEach
    void setUp() {
        bookingDto = new BookingDto(1L, 2L, "FLIGHT", 3L, 4L, 5L, "CONFIRMED", 6L);
    }
 
    @Test
    void createBooking_success() throws Exception {
        Mockito.when(bookingService.createBooking(any())).thenReturn(bookingDto);
 
        mockMvc.perform(post("/api/v1/bookings")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(bookingDto)))
               .andExpect(status().isCreated())
               .andExpect(jsonPath("$.type").value("FLIGHT"));
    }
 
    @Test
    void createBooking_validationError() throws Exception {
        BookingDto invalidDto = new BookingDto();
 
        mockMvc.perform(post("/api/v1/bookings")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidDto)))
               .andExpect(status().isBadRequest());
    }
 
    @Test
    void getBookingById_success() throws Exception {
        Mockito.when(bookingService.getBookingDetailsById(1L)).thenReturn(bookingDto);
 
        mockMvc.perform(get("/api/v1/bookings/1"))
               .andExpect(status().isOk())
               .andExpect(jsonPath("$.bookingId").value(1L));
    }
 
    @Test
    void getBookingById_notFound() throws Exception {
        Mockito.when(bookingService.getBookingDetailsById(1L))
               .thenThrow(new ResourceNotFoundException("Booking", "id", 1L));
 
        mockMvc.perform(get("/api/v1/bookings/1"))
               .andExpect(status().isNotFound());
    }
 
    @Test
    void updateBooking_success() throws Exception {
        Mockito.when(bookingService.updatePackageById(eq(1L), any())).thenReturn(bookingDto);
 
        mockMvc.perform(put("/api/v1/bookings/1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(bookingDto)))
               .andExpect(status().isOk())
               .andExpect(jsonPath("$.type").value("FLIGHT"));
    }
 
    @Test
    void getAllBookings_success() throws Exception {
        BookingResponseDto response = new BookingResponseDto(List.of(bookingDto), 0, 10, 1, 1, true, true);
        Mockito.when(bookingService.getAllBookings(anyInt(), anyInt(), anyString(), anyString()))
               .thenReturn(response);
 
        mockMvc.perform(get("/api/v1/bookings"))
               .andExpect(status().isOk())
               .andExpect(jsonPath("$.content[0].type").value("FLIGHT"));
    }
 
    @Test
    void getBookingsByUserId_success() throws Exception {
        BookingResponseDto response = new BookingResponseDto(List.of(bookingDto), 0, 10, 1, 1, true, true);
        Mockito.when(bookingService.getBookingsByUserId(eq(2L), anyInt(), anyInt(), anyString(), anyString()))
               .thenReturn(response);
 
        mockMvc.perform(get("/api/v1/bookings/user/2"))
               .andExpect(status().isOk())
               .andExpect(jsonPath("$.content[0].userId").value(2L));
    }
 
    @Test
    void getBookingsByType_success() throws Exception {
        BookingResponseDto response = new BookingResponseDto(List.of(bookingDto), 0, 10, 1, 1, true, true);
        Mockito.when(bookingService.getBookingsByType(eq("FLIGHT"), anyInt(), anyInt(), anyString(), anyString()))
               .thenReturn(response);
 
        mockMvc.perform(get("/api/v1/bookings/type/FLIGHT"))
               .andExpect(status().isOk());
    }
 
    @Test
    void getBookingsByStatus_success() throws Exception {
        BookingResponseDto response = new BookingResponseDto(List.of(bookingDto), 0, 10, 1, 1, true, true);
        Mockito.when(bookingService.getBookingsByStatus(eq("CONFIRMED"), anyInt(), anyInt(), anyString(), anyString()))
               .thenReturn(response);
 
        mockMvc.perform(get("/api/v1/bookings/status/CONFIRMED"))
               .andExpect(status().isOk());
    }
 
    @Test
    void getActiveBookings_success() throws Exception {
        BookingResponseDto response = new BookingResponseDto(List.of(bookingDto), 0, 10, 1, 1, true, true);
        Mockito.when(bookingService.getActiveBookings(anyInt(), anyInt(), anyString(), anyString()))
               .thenReturn(response);
 
        mockMvc.perform(get("/api/v1/bookings/active"))
               .andExpect(status().isOk());
    }
}
 