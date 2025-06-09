package com.cts.travelpackage.service;



import java.util.List;

import com.cts.travelpackage.dto.TravelPackageDto;
import com.cts.travelpackage.dto.TravelPackageResponse;
public interface PackageService {

	public TravelPackageDto createPackage(TravelPackageDto travelPackageDto) ;

	public TravelPackageResponse getAllPackages(int PageNo,int pageSize,String sortBy,String sortDir) ;

	public TravelPackageDto getPackageById(Long id) ;
	
	public TravelPackageDto updatePackageById(Long id,TravelPackageDto travelPackageDto);

}
