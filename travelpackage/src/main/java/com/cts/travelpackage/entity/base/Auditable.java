package com.cts.travelpackage.entity.base;

import java.time.LocalDateTime;

import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
@Data
@AllArgsConstructor
@NoArgsConstructor
public abstract class Auditable<U> {
	@CreatedBy
	protected U createdBy;
	
	@CreatedDate
	protected LocalDateTime createdAt;
	
	@LastModifiedBy
	protected U updatedBy;
	
	@LastModifiedDate
	protected LocalDateTime updatedAt;
	
}



