package com.cts.SupportTicket.service;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.stereotype.Service;

import com.cts.SupportTicket.dto.SupportTicketRequestDTO;
import com.cts.SupportTicket.dto.SupportTicketResponseDTO;
import com.cts.SupportTicket.entity.SupportTicket;
import com.cts.SupportTicket.exception.EntityNotFoundException;
import com.cts.SupportTicket.repository.SupportTicketRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class SupportTicketServiceImpl implements SupportTicketService {
	private static final Logger logger = LoggerFactory.getLogger(SupportTicketServiceImpl.class);
	private final SupportTicketRepository repository;

	public SupportTicketServiceImpl(SupportTicketRepository repository) {
		this.repository = repository;
	}

	@Override
	public SupportTicketResponseDTO createTicket(SupportTicketRequestDTO dto) {
		logger.info("Creating new support ticket for userId: {}", dto.getUserId());
		SupportTicket ticket = new SupportTicket();
		ticket.setUserId(dto.getUserId());
		ticket.setIssue(dto.getIssue());
		ticket.setAssignedAgentId(dto.getAssignedAgentId() != null ? dto.getAssignedAgentId() : 0);
		ticket.setStatus(SupportTicket.TicketStatus.PENDING);
		ticket.setCreatedAt(LocalDateTime.now());
		ticket.setUpdatedAt(null);
		SupportTicket savedTicket = repository.save(ticket);
		logger.debug("Support ticket created with id: {}", savedTicket.getTicketId());
		return toResponseDTO(savedTicket);
	}

	@Override
	public List<SupportTicketResponseDTO> getAllTickets() {
		logger.info("Fetching all support tickets");
		return repository.findAll().stream().map(this::toResponseDTO).toList();
	}

	@Override
	public SupportTicketResponseDTO getTicketById(int id) throws EntityNotFoundException {
		logger.info("Fetching support ticket by id: {}", id);
		return toResponseDTO(repository.findById(id)
				.orElseThrow(() -> new EntityNotFoundException("Ticket not found with id: " + id)));
	}

	@Override
	public List<SupportTicketResponseDTO> getTicketsByUserId(int userId) throws EntityNotFoundException {
		logger.info("Fetching tickets for userId: {}", userId);
		List<SupportTicket> tickets = repository.findByUserId(userId);
		if (tickets.isEmpty()) {
			throw new EntityNotFoundException("No Tickets Found for User with ID: " + userId);
		}
		return repository.findByUserId(userId).stream().map(this::toResponseDTO).toList();
	}

	@Override
	public List<SupportTicketResponseDTO> getTicketsByAssignedAgentId(int agentId) throws EntityNotFoundException {
		logger.info("Fetching tickets assigned to agentId: {}", agentId);
		List<SupportTicket> tickets = repository.findByAssignedAgentId(agentId);
		if (tickets.isEmpty()) {
			throw new EntityNotFoundException("agent not found with ID :" + agentId);
		}
		return repository.findByAssignedAgentId(agentId).stream().map(this::toResponseDTO).toList();
	}

	@Override
	public List<SupportTicketResponseDTO> getTicketsByStatus(String status) {
		logger.info("Fetching tickets by status: {}", status);
		SupportTicket.TicketStatus ticketStatus = SupportTicket.TicketStatus.valueOf(status.toUpperCase());
		return repository.findByStatus(ticketStatus).stream().map(this::toResponseDTO).toList();
	}

	@Override
	public SupportTicketResponseDTO updateTicketStatusAndAgent(int ticketId, SupportTicket.TicketStatus status,
			Integer assignedAgentId) throws EntityNotFoundException {
		logger.info("Updating ticket id: {} with status: {} and agentId: {}", ticketId, status, assignedAgentId);
		SupportTicket ticket = repository.findById(ticketId)
				.orElseThrow(() -> new EntityNotFoundException("Ticket not found with id: " + ticketId));
		ticket.setStatus(status);
		ticket.setAssignedAgentId(assignedAgentId);
		ticket.setUpdatedAt(LocalDateTime.now());
		return toResponseDTO(repository.save(ticket));
	}

	@Override
	public SupportTicketResponseDTO updateTicketStatus(int ticketId, SupportTicket.TicketStatus status)
			throws EntityNotFoundException {
		logger.info("Updating ticket id: {} with status: {}", ticketId, status);
		SupportTicket ticket = repository.findById(ticketId)
				.orElseThrow(() -> new EntityNotFoundException("Ticket not found with id: " + ticketId));
		ticket.setStatus(status);
		ticket.setUpdatedAt(LocalDateTime.now());
		return toResponseDTO(repository.save(ticket));
	}

	private SupportTicketResponseDTO toResponseDTO(SupportTicket ticket) {
		SupportTicketResponseDTO dto = new SupportTicketResponseDTO();
		dto.setTicketId(ticket.getTicketId());
		dto.setUserId(ticket.getUserId());
		dto.setIssue(ticket.getIssue());
		dto.setStatus(SupportTicketResponseDTO.TicketStatus.valueOf(ticket.getStatus().name()));
		dto.setAssignedAgentId(ticket.getAssignedAgentId());
		dto.setCreatedAt(ticket.getCreatedAt());
		dto.setUpdatedAt(ticket.getUpdatedAt());
		return dto;
	}
}
