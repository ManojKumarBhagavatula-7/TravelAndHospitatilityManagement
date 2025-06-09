package com.cts.support.ticket.service;

import java.util.List;

import com.cts.support.ticket.dto.SupportTicketRequestDTO;
import com.cts.support.ticket.dto.SupportTicketResponseDTO;
import com.cts.support.ticket.entity.SupportTicket;
import com.cts.support.ticket.exception.EntityNotFoundException;

public interface SupportTicketService {
    SupportTicketResponseDTO createTicket(SupportTicketRequestDTO dto);
    List<SupportTicketResponseDTO> getAllTickets();
    SupportTicketResponseDTO getTicketById(int id) throws EntityNotFoundException;
    List<SupportTicketResponseDTO> getTicketsByUserId(int userId);
    List<SupportTicketResponseDTO> getTicketsByAssignedAgentId(int agentId);
    List<SupportTicketResponseDTO> getTicketsByStatus(String status);
    SupportTicketResponseDTO updateTicketStatusAndAgent(int ticketId, SupportTicket.TicketStatus status, Integer assignedAgentId)throws EntityNotFoundException;
    SupportTicketResponseDTO updateTicketStatus(int ticketId, SupportTicket.TicketStatus status) throws EntityNotFoundException;
}
