package com.cts.travelpackage.service.impl;
 
import com.cts.travelpackage.dto.ItineraryDto;
import com.cts.travelpackage.dto.ItineraryResponse;
import com.cts.travelpackage.dto.TopSellingPackageDto;
import com.cts.travelpackage.entity.Itinerary;
import com.cts.travelpackage.entity.TravelPackage;
import com.cts.travelpackage.exception.ResourceNotFoundException;
import com.cts.travelpackage.repository.ItineraryRepository;
import com.cts.travelpackage.repository.PackageRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.modelmapper.ModelMapper;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.*;
import org.springframework.test.context.ActiveProfiles;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
 
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;


@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
class ItineraryServiceImplTest {
 
    @Mock
    private ItineraryRepository itineraryRepo;
 
    @Mock
    private PackageRepository packageRepo;
 
    @Mock
    private ModelMapper mapper;
    
	@Mock
	private ValidationService validationService;

 
    @InjectMocks
    private ItineraryServiceImpl itineraryService;
 
    private Itinerary itinerary;
    private ItineraryDto itineraryDto;
 
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
 
        itinerary = new Itinerary();
        itinerary.setItineraryId(1L);
        itinerary.setUserId(10L);
        itinerary.setCustomizationDetails("Luxury");
        itinerary.setPrice(new BigDecimal("2000"));
 
        TravelPackage travelPackage = new TravelPackage();
        travelPackage.setPackageId(101L);
        itinerary.setTravelPackage(travelPackage);
 
        itineraryDto = new ItineraryDto();
        itineraryDto.setItineraryId(1L);
        itineraryDto.setUserId(10L);
        itineraryDto.setCustomizationDetails("Luxury");
        itineraryDto.setPrice(new BigDecimal("2000"));
        itineraryDto.setTravelPackageId(101L);
    }
 // ------------------ createItinerary ------------------
    @Test
    void createItinerary_success_withPackage() {
        TravelPackage travelPackage = new TravelPackage();
        travelPackage.setPackageId(101L);
 
        when(packageRepo.findById(101L)).thenReturn(Optional.of(travelPackage));
        when(mapper.map(itineraryDto, Itinerary.class)).thenReturn(itinerary);
        when(itineraryRepo.save(itinerary)).thenReturn(itinerary);
        when(mapper.map(itinerary, ItineraryDto.class)).thenReturn(itineraryDto);
 
        ItineraryDto result = itineraryService.createItinerary(itineraryDto);
 
        assertThat(result).isNotNull();
        assertThat(result.getTravelPackageId()).isEqualTo(101L);
    }
 
    @Test
    void createItinerary_packageNotFound() {
        when(packageRepo.findById(101L)).thenReturn(Optional.empty());
 
        assertThatThrownBy(() -> itineraryService.createItinerary(itineraryDto))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("TravelPackage");
    }
    // ------------------ getAllItineraries ------------------

    @Test
    void getAllItineraries_success() {
        Page<Itinerary> page = new PageImpl<>(List.of(itinerary));
        when(itineraryRepo.findAll(any(Pageable.class))).thenReturn(page);
        when(mapper.map(any(Itinerary.class), eq(ItineraryDto.class))).thenReturn(itineraryDto);
 
        ItineraryResponse response = itineraryService.getAllItineraries(0, 10, "itineraryId", "asc");
 
        assertThat(response.getContent()).hasSize(1);
        assertThat(response.getContent().get(0).getUserId()).isEqualTo(10L);
    }
 
    @Test
    void getAllItineraries_emptyList() {
        when(itineraryRepo.findAll(any(Pageable.class))).thenReturn(new PageImpl<>(List.of()));
 
        ItineraryResponse response = itineraryService.getAllItineraries(0, 5, "id", "desc");
 
        assertThat(response.getContent()).isEmpty();
        assertThat(response.getPageNo()).isEqualTo(0);
    }
    // ------------------ getitineraryById ------------------

    @Test
    void getItineraryById_success() {
        when(itineraryRepo.findById(1L)).thenReturn(Optional.of(itinerary));
        when(mapper.map(itinerary, ItineraryDto.class)).thenReturn(itineraryDto);
 
        ItineraryDto result = itineraryService.getItineraryById(1L);
        assertThat(result.getUserId()).isEqualTo(10L);
    }
 
    @Test
    void getItineraryById_notFound() {
        when(itineraryRepo.findById(99L)).thenReturn(Optional.empty());
 
        assertThatThrownBy(() -> itineraryService.getItineraryById(99L))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Itinerary");
    }
 
    @Test
    void updateItineraryById_success() {
        TravelPackage travelPackage = new TravelPackage();
        travelPackage.setPackageId(101L);
 
        when(itineraryRepo.findById(1L)).thenReturn(Optional.of(itinerary));
        when(packageRepo.findById(101L)).thenReturn(Optional.of(travelPackage));
        when(itineraryRepo.save(any(Itinerary.class))).thenReturn(itinerary);
        when(mapper.map(itinerary, ItineraryDto.class)).thenReturn(itineraryDto);
 
        ItineraryDto updated = itineraryService.updateItineraryById(1L, itineraryDto);
 
        assertThat(updated.getUserId()).isEqualTo(10L);
        verify(itineraryRepo).save(any(Itinerary.class));
    }
    // ------------------ updateItineraryById ------------------

    @Test
    void updateItineraryById_itineraryNotFound() {
        when(itineraryRepo.findById(1L)).thenReturn(Optional.empty());
 
        assertThatThrownBy(() -> itineraryService.updateItineraryById(1L, itineraryDto))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Itinerary");
    }
 
    @Test
    void updateItineraryById_packageNotFound() {
        when(itineraryRepo.findById(1L)).thenReturn(Optional.of(itinerary));
        when(packageRepo.findById(101L)).thenReturn(Optional.empty());
 
        assertThatThrownBy(() -> itineraryService.updateItineraryById(1L, itineraryDto))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("TravelPackage");
    }
    
    // ------------------ topSellingPackages ------------------

    @Test
    void getTopSellingPackages_success() {
        TopSellingPackageDto dto = new TopSellingPackageDto(
            1L, // packageId
            "Beach Blast", // name
            new BigDecimal("999.99"), // price
            25L // salesCount
        );

        List<TopSellingPackageDto> topPackages = List.of(dto);

        when(itineraryRepo.findTopSellingPackagesWithDetails(any(Pageable.class))).thenReturn(topPackages);

        List<TopSellingPackageDto> result = itineraryService.getTopSellingPackages(3);

        assertThat(result).hasSize(1);
        assertThat(result.get(0).getName()).isEqualTo("Beach Blast");
    }

 
    @Test
    void getTopSellingPackages_emptyList() {
        when(itineraryRepo.findTopSellingPackagesWithDetails(any(Pageable.class))).thenReturn(List.of());
 
        List<TopSellingPackageDto> result = itineraryService.getTopSellingPackages(5);
        assertThat(result).isEmpty();
    }
}
 