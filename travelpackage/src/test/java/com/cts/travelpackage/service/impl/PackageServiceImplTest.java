package com.cts.travelpackage.service.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

import java.math.BigDecimal;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.test.context.ActiveProfiles;

import com.cts.travelpackage.dto.TravelPackageDto;
import com.cts.travelpackage.dto.TravelPackageResponse;
import com.cts.travelpackage.entity.TravelPackage;
import com.cts.travelpackage.exception.BadRequestException;
import com.cts.travelpackage.exception.ConflictException;
import com.cts.travelpackage.exception.ForbiddenException;
import com.cts.travelpackage.exception.ResourceNotFoundException;
import com.cts.travelpackage.exception.UnauthorizedException;
import com.cts.travelpackage.repository.PackageRepository;

import jakarta.validation.ConstraintViolationException;


@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
public class PackageServiceImplTest {
	
	@Mock
    private PackageRepository packageRepository;
 
    @Mock
    private ModelMapper mapper;
    
    @Mock
    private ValidationService validationService;
    
    @InjectMocks
    private PackageServiceImpl packageService;
    
    private TravelPackageDto validDto;
    private TravelPackage mappedEntity;
    
    @BeforeEach
    void setUp() {
        
        validDto = new TravelPackageDto();
        validDto.setPackageName("Deluxe Europe Trip");
        validDto.setIncludedFlightIds(Arrays.asList(101L, 102L));
        validDto.setIncludedHotelIds(Arrays.asList(201L, 202L));
        validDto.setActivities(Arrays.asList("Sightseeing", "Cruise"));
        validDto.setPrice(BigDecimal.valueOf(999.99));
 
        mappedEntity = new TravelPackage();
        mappedEntity.setPackageId(1L);
        mappedEntity.setPackageName(validDto.getPackageName());
        mappedEntity.setIncludedFlightIds(validDto.getIncludedFlightIds());
        mappedEntity.setIncludedHotelIds(validDto.getIncludedHotelIds());
        mappedEntity.setActivities(validDto.getActivities());
        mappedEntity.setPrice(validDto.getPrice());
    }
    
 // ------------------ createPackage ------------------
    
    @Test
    void testCreatePackage_success() {
		when(mapper.map(validDto, TravelPackage.class)).thenReturn(mappedEntity);
		when(packageRepository.save(mappedEntity)).thenReturn(mappedEntity);
		when(mapper.map(mappedEntity, TravelPackageDto.class)).thenReturn(validDto);
 
        TravelPackageDto result = packageService.createPackage(validDto);
        assertNotNull(result);
        assertEquals(validDto.getPackageName(), result.getPackageName());
    }
    
    @Test
    void testCreatePackage_badRequest_priceNull() {
        validDto.setPrice(null);
        doThrow(new BadRequestException("Price cannot be null"))
        .when(validationService).validate(validDto);
        assertThrows(BadRequestException.class, () -> packageService.createPackage(validDto));
    }
    
    @Test
    void testCreatePackage_conflict_duplicatePackageName() {
		when(mapper.map(validDto, TravelPackage.class)).thenReturn(mappedEntity);
		when(packageRepository.save(mappedEntity)).thenThrow(new ConflictException("Duplicate package"));
 
        assertThrows(ConflictException.class, () -> packageService.createPackage(validDto));
    }
    
//    @Test
//    void testCreatePackage_internalServerError() {
//		when(mapper.map(validDto, TravelPackage.class)).thenReturn(mappedEntity);
//		when(packageRepository.save(mappedEntity)).thenThrow(new RuntimeException("DB down"));
// 
//        assertThrows(InternalServerErrorException.class, () -> packageService.createPackage(validDto));
//    }
    
    @Test
    void testCreatePackage_missingPackageName() {
        validDto.setPackageName(""); 
     
        doThrow(new ConstraintViolationException("Package name is required", null))
            .when(validationService).validate(validDto);
     
        assertThrows(ConstraintViolationException.class, () -> packageService.createPackage(validDto));
    }
    
    @Test
    void testCreatePackage_nullDto() {
        assertThrows(BadRequestException.class, () -> packageService.createPackage(null));
    }
    
    
    // ------------------ getPackageById ------------------

	@Test
	void testGetPackageById_success() {
		when(packageRepository.findById(1L)).thenReturn(Optional.of(mappedEntity));
		when(mapper.map(mappedEntity, TravelPackageDto.class)).thenReturn(validDto);

		TravelPackageDto result = packageService.getPackageById(1L);
		assertEquals(validDto.getPackageName(), result.getPackageName());
	}

	@Test
	void testGetPackageById_notFound() {
		when(packageRepository.findById(99L)).thenReturn(Optional.empty());
		assertThrows(ResourceNotFoundException.class, () -> packageService.getPackageById(99L));
	}

	@Test
	void testGetPackageById_forbiddenAccess() {
		when(packageRepository.findById(1L)).thenThrow(new ForbiddenException("Access denied"));
		assertThrows(ForbiddenException.class, () -> packageService.getPackageById(1L));
	}
	 // ------------------ updatePackageById ------------------
	@Test
	void testUpdatePackage_success() {
		TravelPackage updatedEntity = new TravelPackage();
		updatedEntity.setPackageId(1L);
		updatedEntity.setPackageName("Updated Tour");

		TravelPackageDto updatedDto = new TravelPackageDto();
		updatedDto.setPackageName("Updated Tour");

		when(packageRepository.findById(1L)).thenReturn(Optional.of(mappedEntity));
		when(packageRepository.save(any())).thenReturn(updatedEntity);
		when(mapper.map(updatedEntity, TravelPackageDto.class)).thenReturn(updatedDto);

		TravelPackageDto result = packageService.updatePackageById(1L, updatedDto);
		assertEquals("Updated Tour", result.getPackageName());
	}

    @Test
    void testUpdatePackage_notFound() {
        when(packageRepository.findById(2L)).thenReturn(Optional.empty());
        assertThrows(ResourceNotFoundException.class, () -> packageService.updatePackageById(2L, validDto));
    }
 
    @Test
    void testUpdatePackage_unauthorized() {
        when(packageRepository.findById(1L)).thenThrow(new UnauthorizedException("Token invalid"));
        assertThrows(UnauthorizedException.class, () -> packageService.updatePackageById(1L, validDto));
    }
 // ------------------ getAllPackages ------------------
	@Test
	void testGetAllPackages_success() {
		Pageable pageable = PageRequest.of(0, 2, Sort.by("price").ascending());
		List<TravelPackage> contentList = Arrays.asList(mappedEntity, mappedEntity);
		Page<TravelPackage> pageResult = new PageImpl<>(contentList);

		when(packageRepository.findAll(pageable)).thenReturn(pageResult);
		when(mapper.map(any(TravelPackage.class), eq(TravelPackageDto.class))).thenReturn(validDto);

		TravelPackageResponse response = packageService.getAllPackages(0, 2, "price", "asc");
		assertEquals(2, response.getContent().size());
	}


    //new comment for git
	@Test
	void newTest() {
		
	}

}


