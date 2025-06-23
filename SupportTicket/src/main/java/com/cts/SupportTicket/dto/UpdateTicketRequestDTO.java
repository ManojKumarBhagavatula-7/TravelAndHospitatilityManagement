package com.cts.SupportTicket.dto;

import com.cts.SupportTicket.entity.SupportTicket;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateTicketRequestDTO {
    public SupportTicket.TicketStatus getStatus() {
		return status;
	}
	public void setStatus(SupportTicket.TicketStatus status) {
		this.status = status;
	}
	public Integer getAssignedAgentId() {
		return assignedAgentId;
	}
	public void setAssignedAgentId(Integer assignedAgentId) {
		this.assignedAgentId = assignedAgentId;
	}
	private SupportTicket.TicketStatus status;
    private Integer assignedAgentId;

  
}