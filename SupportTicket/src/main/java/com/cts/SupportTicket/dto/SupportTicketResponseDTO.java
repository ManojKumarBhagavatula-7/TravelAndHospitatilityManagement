package com.cts.SupportTicket.dto;

import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SupportTicketResponseDTO {
    private int ticketId;
    private int userId;
    private TicketStatus status;
    private String issue;
	private int assignedAgentId;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    
    public enum TicketStatus {
        PENDING,
        COMPLETED
    }


}

