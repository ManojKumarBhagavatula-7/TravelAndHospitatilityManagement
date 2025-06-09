package com.cts.support.ticket.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cts.support.ticket.entity.SupportTicket;



public interface SupportTicketRepository extends JpaRepository<SupportTicket, Integer> {
    List<SupportTicket> findByUserId(int userId);
    List<SupportTicket> findByAssignedAgentId(int assignedAgentId);
    List<SupportTicket> findByStatus(SupportTicket.TicketStatus status);

}
