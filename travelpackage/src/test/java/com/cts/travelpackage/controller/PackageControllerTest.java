package com.cts.travelpackage.controller;
 
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.math.BigDecimal;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.cts.travelpackage.config.TestSecurityConfig;
import com.cts.travelpackage.dto.TravelPackageDto;
import com.cts.travelpackage.dto.TravelPackageResponse;
import com.cts.travelpackage.exception.ResourceNotFoundException;
import com.cts.travelpackage.service.PackageService;
import com.fasterxml.jackson.databind.ObjectMapper;
 
@WebMvcTest(PackageController.class)
@Import(TestSecurityConfig.class)
class PackageControllerTest {
 
    @Autowired
    private MockMvc mockMvc;
 
    @MockBean
    private PackageService packageService;
 
    @Autowired
    private ObjectMapper objectMapper;
 
    private TravelPackageDto sampleDto;
 
    @BeforeEach
    void setUp() {
        sampleDto = new TravelPackageDto();
        sampleDto.setPackageId(1L);
        sampleDto.setPackageName("Europe Explorer");
        sampleDto.setIncludedFlightIds(List.of(101L));
        sampleDto.setIncludedHotelIds(List.of(201L));
        sampleDto.setActivities(List.of("Skiing"));
        sampleDto.setPrice(new BigDecimal("1500.00"));
    }
 
    // ------------------ POST /packages ------------------
    @Test
    void createPackage_success() throws Exception {
        when(packageService.createPackage(any())).thenReturn(sampleDto);
 
        mockMvc.perform(post("/api/v1/packages")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(sampleDto)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.packageName").value("Europe Explorer"));
    }
 
    @Test
    void createPackage_validationFailure() throws Exception {
        sampleDto.setPackageName("");  // invalid name
 
        mockMvc.perform(post("/api/v1/packages")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(sampleDto)))
                .andExpect(status().isBadRequest());
    }
 
    // ------------------ GET /packages ------------------
    @Test
    void getAllPackages_success() throws Exception {
        TravelPackageResponse response = new TravelPackageResponse();
        response.setContent(List.of(sampleDto));
        response.setPageNo(0);
        response.setPageSize(10);
 
        when(packageService.getAllPackages(0, 10, "packageName", "asc")).thenReturn(response);
 
        mockMvc.perform(get("/api/v1/packages")
                        .param("pageNo", "0")
                        .param("pageSize", "10")
                        .param("sortBy", "packageName")
                        .param("sortDir", "asc"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray());
    }
 
    @Test
    void getAllPackages_internalError() throws Exception {
        when(packageService.getAllPackages(anyInt(), anyInt(), anyString(), anyString()))
                .thenThrow(new RuntimeException("Unexpected"));
 
        mockMvc.perform(get("/api/v1/packages"))
                .andExpect(status().isInternalServerError());
    }
 
    // ------------------ GET /packages/{id} ------------------
    @Test
    void getPackageById_success() throws Exception {
        when(packageService.getPackageById(1L)).thenReturn(sampleDto);
 
        mockMvc.perform(get("/api/v1/packages/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.packageId").value(1));
    }
 
    @Test
    void getPackageById_notFound() throws Exception {
        when(packageService.getPackageById(99L))
                .thenThrow(new ResourceNotFoundException("TravelPackage", "id", 99L));
 
        mockMvc.perform(get("/api/v1/packages/99"))
                .andExpect(status().isNotFound());
    }
 
    // ------------------ PUT /packages/{id} ------------------
    @Test
    void updatePackageById_success() throws Exception {
        when(packageService.updatePackageById(eq(1L), any())).thenReturn(sampleDto);
 
        mockMvc.perform(put("/api/v1/packages/1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(sampleDto)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.packageName").value("Europe Explorer"));
    }
 
    @Test
    void updatePackageById_validationFailure() throws Exception {
        sampleDto.setPrice(null);  // invalid
 
        mockMvc.perform(put("/api/v1/packages/1")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(sampleDto)))
                .andExpect(status().isBadRequest());
    }
 
    @Test
    void updatePackageById_notFound() throws Exception {
        when(packageService.updatePackageById(eq(999L), any()))
                .thenThrow(new ResourceNotFoundException("TravelPackage", "id", 999L));
 
        mockMvc.perform(put("/api/v1/packages/999")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(sampleDto)))
                .andExpect(status().isNotFound());
    }
}
 