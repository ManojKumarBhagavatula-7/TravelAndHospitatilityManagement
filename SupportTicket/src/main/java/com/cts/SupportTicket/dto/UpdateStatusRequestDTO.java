package com.cts.SupportTicket.dto;

import com.cts.SupportTicket.entity.SupportTicket;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateStatusRequestDTO {
    private SupportTicket.TicketStatus status;

	public SupportTicket.TicketStatus getStatus() {
		return status;
	}

	public void setStatus(SupportTicket.TicketStatus status) {
		this.status = status;
	}
}
