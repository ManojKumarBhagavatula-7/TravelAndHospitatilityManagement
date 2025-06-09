package com.cts.travelpackage.dto;

import java.util.List;
import lombok.Data;

@Data
public class TravelPackageResponse {

	private List<TravelPackageDto> content;
	private int pageNo;
	private int pageSize;
	private long totalElements;
	private int totalPages;
	private boolean last;
	private boolean first;
}
