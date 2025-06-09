package com.cts.travelpackage.dto;


import java.math.BigDecimal;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TopSellingPackageDto {

    private Long packageId;
    private String name;
    private BigDecimal price;
    private Long salesCount;

    public TopSellingPackageDto(Long packageId, String name, BigDecimal price, Long salesCount) {
        this.packageId = packageId;
        this.name = name;
        this.price = price;
        this.salesCount = salesCount;
    }

}

