package com.cts.support.ticket.dto;

import com.cts.support.ticket.entity.SupportTicket;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateTicketRequestDTO {
    private SupportTicket.TicketStatus status;
    private Integer assignedAgentId;

  
}