package com.cts.support.ticket.dto;

import com.cts.support.ticket.entity.SupportTicket;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateStatusRequestDTO {
    private SupportTicket.TicketStatus status;
}
