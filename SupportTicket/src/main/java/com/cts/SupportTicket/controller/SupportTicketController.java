package com.cts.SupportTicket.controller;

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.cts.SupportTicket.dto.SupportTicketRequestDTO;
import com.cts.SupportTicket.dto.SupportTicketResponseDTO;
import com.cts.SupportTicket.dto.UpdateStatusRequestDTO;
import com.cts.SupportTicket.dto.UpdateTicketRequestDTO;
import com.cts.SupportTicket.exception.EntityNotFoundException;
import com.cts.SupportTicket.service.SupportTicketService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Controller for managing support tickets.
 * Provides endpoints for creating, viewing, and updating support tickets.
 */
@RestController
@RequestMapping("/api/support-tickets")
public class SupportTicketController {

    private static final Logger logger = LoggerFactory.getLogger(SupportTicketController.class);
    private final SupportTicketService service;

    /**
     * Constructor for SupportTicketController.
     *
     * @param service the service layer for handling support ticket operations
     */
    public SupportTicketController(SupportTicketService service) {
        this.service = service;
    }

    /**
     * Fetches all support tickets.
     *
     * @return a list of all support tickets
     */
    @GetMapping
    public ResponseEntity<List<SupportTicketResponseDTO>> getAllTickets() {
        logger.info("Fetching all support tickets");
        List<SupportTicketResponseDTO> tickets = service.getAllTickets();
        logger.debug("Found {} tickets", tickets.size());
        return ResponseEntity.ok(tickets);
    }

    /**
     * Fetches tickets for a specific user.
     *
     * @param userId the ID of the user
     * @return a list of tickets for the specified user
     */
    @GetMapping("/user/{userId}")
    public ResponseEntity<List<SupportTicketResponseDTO>> getUserTickets(@PathVariable int userId) throws EntityNotFoundException {
        logger.info("Fetching tickets for userId={}", userId);
        List<SupportTicketResponseDTO> tickets = service.getTicketsByUserId(userId);
        logger.debug("User {} has {} tickets", userId, tickets.size());
        return ResponseEntity.ok(tickets);
    }

    /**
     * Fetches tickets for a specific user filtered by status.
     *
     * @param userId the ID of the user
     * @param status the status of the tickets
     * @return a list of tickets for the specified user and status
     * @throws EntityNotFoundException 
     */
    @GetMapping("/user/{userId}/status/{status}")
    public ResponseEntity<List<SupportTicketResponseDTO>> getUserTicketsByStatus(
            @PathVariable int userId,
            @PathVariable SupportTicketResponseDTO.TicketStatus status) throws EntityNotFoundException {
        logger.info("Fetching tickets for userId={} with status={}", userId, status);
        List<SupportTicketResponseDTO> filtered = service.getTicketsByUserId(userId).stream()
                .filter(t -> t.getStatus().equals(status))
                .toList();
        logger.debug("User {} has {} tickets with status {}", userId, filtered.size(), status);
        return ResponseEntity.ok(filtered);
    }

    /**
     * Fetches tickets assigned to a specific agent.
     *
     * @param agentId the ID of the agent
     * @return a list of tickets assigned to the specified agent
     */
    @GetMapping("/agent/{agentId}")
    public ResponseEntity<List<SupportTicketResponseDTO>> getAgentTickets(@PathVariable int agentId)throws EntityNotFoundException {
        logger.info("Fetching tickets assigned to agentId={}", agentId);
        List<SupportTicketResponseDTO> tickets = service.getTicketsByAssignedAgentId(agentId);
        logger.debug("Agent {} has {} assigned tickets", agentId, tickets.size());
        return ResponseEntity.ok(tickets);
    }

    /**
     * Fetches tickets assigned to a specific agent filtered by status.
     *
     * @param agentId the ID of the agent
     * @param status  the status of the tickets
     * @return a list of tickets assigned to the specified agent and status
     * @throws EntityNotFoundException 
     */
    @GetMapping("/agent/{agentId}/status/{status}")
    public ResponseEntity<List<SupportTicketResponseDTO>> getAgentTicketsByStatus(
            @PathVariable int agentId,
            @PathVariable SupportTicketResponseDTO.TicketStatus status) throws EntityNotFoundException {
        logger.info("Fetching tickets for agentId={} with status={}", agentId, status);
        List<SupportTicketResponseDTO> filtered = service.getTicketsByAssignedAgentId(agentId).stream()
                .filter(t -> t.getStatus().equals(status))
                .toList();
        logger.debug("Agent {} has {} tickets with status {}", agentId, filtered.size(), status);
        return ResponseEntity.ok(filtered);
    }

    /**
     * Creates a new support ticket.
     *
     * @param ticket the details of the ticket to be created
     * @return the created support ticket
     */
    @PostMapping
    public ResponseEntity<SupportTicketResponseDTO> createTicket(@RequestBody SupportTicketRequestDTO ticket) {
        logger.info("Creating new support ticket for userId={}", ticket.getUserId());
        SupportTicketResponseDTO created = service.createTicket(ticket);
        logger.debug("Created ticket with id={}", created.getUserId());
        return ResponseEntity.status(201).body(created);
    }

    /**
     * Assigns an agent and updates the status of a ticket.
     *
     * @param ticketId the ID of the ticket
     * @param request  the details of the agent and status to be updated
     * @return the updated support ticket
     * @throws EntityNotFoundException if the ticket is not found
     */
    @PutMapping("/{ticketId}/assign")
    public ResponseEntity<SupportTicketResponseDTO> assignAgentAndStatus(
            @PathVariable int ticketId,
            @RequestBody UpdateTicketRequestDTO request) throws EntityNotFoundException {
        logger.info("Assigning agentId={} and status={} to ticketId={}", request.getAssignedAgentId(), request.getStatus(), ticketId);
        SupportTicketResponseDTO updated = service.updateTicketStatusAndAgent(ticketId, request.getStatus(), request.getAssignedAgentId());
        logger.debug("Updated ticketId={} with new agent and status", ticketId);
        return ResponseEntity.ok(updated);
    }

    /**
     * Updates the status of a ticket.
     *
     * @param ticketId the ID of the ticket
     * @param request  the new status to be updated
     * @return the updated support ticket
     * @throws EntityNotFoundException if the ticket is not found
     */
    @PutMapping("/{ticketId}/status")
    public ResponseEntity<SupportTicketResponseDTO> updateStatus(
            @PathVariable int ticketId,
            @RequestBody UpdateStatusRequestDTO request) throws EntityNotFoundException {
        logger.info("Updating status of ticketId={} to {}", ticketId, request.getStatus());
        SupportTicketResponseDTO updated = service.updateTicketStatus(ticketId, request.getStatus());
        logger.debug("Updated ticketId={} with new status", ticketId);
        return ResponseEntity.ok(updated);
    }
}
