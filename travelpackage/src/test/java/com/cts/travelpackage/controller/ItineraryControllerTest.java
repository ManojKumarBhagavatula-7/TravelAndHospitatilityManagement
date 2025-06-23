package com.cts.travelpackage.controller;
 
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content; // ✅ Correct import
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.math.BigDecimal;
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
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import com.cts.travelpackage.config.TestSecurityConfig;
import com.cts.travelpackage.dto.ItineraryDto;
import com.cts.travelpackage.dto.ItineraryResponse;
import com.cts.travelpackage.dto.TopSellingPackageDto;
import com.cts.travelpackage.exception.ResourceNotFoundException;
import com.cts.travelpackage.service.ItineraryService;
import com.fasterxml.jackson.databind.ObjectMapper;
 
@WebMvcTest(ItineraryController.class)
@Import(TestSecurityConfig.class)
public class ItineraryControllerTest {
 
    @Autowired
    private MockMvc mockMvc;
 
    @MockBean
    private ItineraryService itineraryService;
 
    @Autowired
    private ObjectMapper objectMapper;
 
    private ItineraryDto itineraryDto;
 
    @BeforeEach
    void setUp() {
        itineraryDto = new ItineraryDto();
        itineraryDto.setItineraryId(1L);
        itineraryDto.setUserId(101L);
        itineraryDto.setCustomizationDetails("Custom Trip to Goa");
        itineraryDto.setPrice(new BigDecimal("2500.00"));
        itineraryDto.setTravelPackageId(5L);
    }
 
    @Test
    void testCreateItinerary_Success() throws Exception {
        Mockito.when(itineraryService.createItinerary(any(ItineraryDto.class))).thenReturn(itineraryDto);
 
        mockMvc.perform(MockMvcRequestBuilders.post("/api/v1/itineraries")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(itineraryDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(101L))
                .andExpect(jsonPath("$.price").value(2500.00));
    }
 
    @Test
    void testCreateItinerary_ValidationFailure() throws Exception {
        itineraryDto.setPrice(null);
 
        mockMvc.perform(MockMvcRequestBuilders.post("/api/v1/itineraries")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(itineraryDto)))
                .andExpect(status().isBadRequest());
    }
 
    @Test
    void testGetAllItineraries_Success() throws Exception {
        ItineraryResponse response = new ItineraryResponse();
        response.setContent(List.of(itineraryDto));
        response.setPageNo(0);
        response.setPageSize(10);
        response.setTotalElements(1L);
        response.setTotalPages(1);
        response.setLast(true);
 
        Mockito.when(itineraryService.getAllItineraries(0, 10, "itineraryId", "asc")).thenReturn(response);
 
        mockMvc.perform(MockMvcRequestBuilders.get("/api/v1/itineraries")
                        .param("pageNo", "0")
                        .param("pageSize", "10")
                        .param("sortBy", "itineraryId")
                        .param("sortDir", "asc"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].userId").value(101L));
    }
 
    @Test
    void testUpdateItinerary_Success() throws Exception {
        Mockito.when(itineraryService.updateItineraryById(eq(1L), any(ItineraryDto.class))).thenReturn(itineraryDto);
 
        mockMvc.perform(MockMvcRequestBuilders.put("/api/v1/itineraries/1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(itineraryDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.itineraryId").value(1L));
    }
 
    @Test
    void testUpdateItinerary_NotFound() throws Exception {
        Mockito.when(itineraryService.updateItineraryById(eq(1L), any(ItineraryDto.class)))
                .thenThrow(new ResourceNotFoundException("Itinerary", "id", 1L));
 
        mockMvc.perform(MockMvcRequestBuilders.put("/api/v1/itineraries/1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(itineraryDto)))
                .andExpect(status().isNotFound());
    }
 
    @Test
    void testGetItineraryById_Success() throws Exception {
        Mockito.when(itineraryService.getItineraryById(1L)).thenReturn(itineraryDto);
 
        mockMvc.perform(MockMvcRequestBuilders.get("/api/v1/itineraries/1"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.itineraryId").value(1L));
    }
 
    @Test
    void testGetItineraryById_NotFound() throws Exception {
        Mockito.when(itineraryService.getItineraryById(1L))
                .thenThrow(new ResourceNotFoundException("Itinerary", "id", 1L));
 
        mockMvc.perform(MockMvcRequestBuilders.get("/api/v1/itineraries/1"))
                .andExpect(status().isNotFound());
    }
 
    @Test
    void testGetTopSellingPackages_Success() throws Exception {
        TopSellingPackageDto top1 = new TopSellingPackageDto(1L, "Goa Delight", new BigDecimal("999.99"), 120L);
        TopSellingPackageDto top2 = new TopSellingPackageDto(2L, "Manali Escape", new BigDecimal("799.99"), 95L);

        Mockito.when(itineraryService.getTopSellingPackages(2)).thenReturn(List.of(top1, top2));

        mockMvc.perform(MockMvcRequestBuilders.get("/api/v1/itineraries/dashboard/topsellingpackages")
                        .param("limit", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].name").value("Goa Delight"))
                .andExpect(jsonPath("$[1].salesCount").value(95));
    }

   
    @Test
    void testGetTopSellingPackages_Empty() throws Exception {
        Mockito.when(itineraryService.getTopSellingPackages(3)).thenReturn(List.of());

        mockMvc.perform(get("/api/v1/itineraries/dashboard/topsellingpackages")
                        .param("limit", "3"))
                .andExpect(status().isOk())
                .andExpect(content().string("[]"));
    }


}
 