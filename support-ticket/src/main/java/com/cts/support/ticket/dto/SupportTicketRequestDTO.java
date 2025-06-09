package com.cts.support.ticket.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SupportTicketRequestDTO {
    private int userId;
    private Integer assignedAgentId;
    private String issue;
	


   
}


