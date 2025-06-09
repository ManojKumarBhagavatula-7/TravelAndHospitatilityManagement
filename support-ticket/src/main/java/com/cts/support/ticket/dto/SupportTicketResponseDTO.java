package com.cts.support.ticket.dto;

import java.time.LocalDateTime;

import com.cts.support.ticket.entity.SupportTicket;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SupportTicketResponseDTO {
    private int ticketId;
    private int userId;
    private String issue;
    private String status;
    private int assignedAgentId;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

}

