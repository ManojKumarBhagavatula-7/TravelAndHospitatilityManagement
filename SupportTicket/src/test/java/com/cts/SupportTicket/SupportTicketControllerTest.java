package com.cts.SupportTicket;


import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.cts.SupportTicket.controller.SupportTicketController;
import com.cts.SupportTicket.dto.SupportTicketRequestDTO;
import com.cts.SupportTicket.dto.SupportTicketResponseDTO;
import com.cts.SupportTicket.dto.SupportTicketResponseDTO.TicketStatus;
import com.cts.SupportTicket.entity.SupportTicket;
import com.cts.SupportTicket.exception.EntityNotFoundException;
import com.cts.SupportTicket.exception.GlobalExceptionHandler;
import com.cts.SupportTicket.service.SupportTicketService;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

@WebMvcTest(SupportTicketController.class)
@ContextConfiguration(classes = {SupportTicketController.class})
@Import(GlobalExceptionHandler.class)
 class SupportTicketControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SupportTicketService service;

    @Test
     void testGetAllTickets_Success() throws Exception {
       SupportTicketResponseDTO ticket1 = new SupportTicketResponseDTO();
        ticket1.setTicketId(1);
        ticket1.setUserId(100);
        ticket1.setIssue("Login issue");
        ticket1.setStatus(TicketStatus.PENDING);
        ticket1.setAssignedAgentId(101);
        ticket1.setCreatedAt(LocalDateTime.now());

        SupportTicketResponseDTO ticket2 = new SupportTicketResponseDTO();
        ticket2.setTicketId(2);
        ticket2.setUserId(101);
        ticket2.setIssue("Payment issue");
        ticket2.setStatus(TicketStatus.COMPLETED);
        ticket2.setAssignedAgentId(102);
        ticket2.setCreatedAt(LocalDateTime.now());

        List<SupportTicketResponseDTO> tickets = Arrays.asList(ticket1, ticket2);

        Mockito.when(service.getAllTickets()).thenReturn(tickets);

        mockMvc.perform(get("/api/support-tickets"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.size()", is(2)))
                .andExpect(jsonPath("$[0].ticketId", is(1)))
                .andExpect(jsonPath("$[0].issue", is("Login issue")))
                .andExpect(jsonPath("$[1].ticketId", is(2)))
                .andExpect(jsonPath("$[1].status", is("COMPLETED")));
    }
    @Test
     void testGetUserTickets_Success() throws Exception {
        SupportTicketResponseDTO ticket = new SupportTicketResponseDTO();
        ticket.setTicketId(1);
        ticket.setUserId(100);
        ticket.setIssue("Login issue");
        ticket.setStatus(TicketStatus.PENDING);
        ticket.setAssignedAgentId(101);
        ticket.setCreatedAt(LocalDateTime.now());

        Mockito.when(service.getTicketsByUserId(100)).thenReturn(List.of(ticket));

        mockMvc.perform(get("/api/support-tickets/user/100"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.size()", is(1)))
                .andExpect(jsonPath("$[0].userId", is(100)))
                .andExpect(jsonPath("$[0].status", is("PENDING")));
    }
    @Test
     void testGetUserTicketsByStatus_Success() throws Exception {
        SupportTicketResponseDTO ticket1 = new SupportTicketResponseDTO();
        ticket1.setTicketId(1);
        ticket1.setUserId(100);
        ticket1.setIssue("Login issue");
        ticket1.setStatus(TicketStatus.PENDING);

        SupportTicketResponseDTO ticket2 = new SupportTicketResponseDTO();
        ticket2.setTicketId(2);
        ticket2.setUserId(100);
        ticket2.setIssue("Payment issue");
        ticket2.setStatus(TicketStatus.COMPLETED);

        Mockito.when(service.getTicketsByUserId(100)).thenReturn(List.of(ticket1, ticket2));

        mockMvc.perform(get("/api/support-tickets/user/100/status/PENDING"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.size()", is(1)))
                .andExpect(jsonPath("$[0].status", is("PENDING")));
    }


    @Test
     void testGetAgentTickets_Success() throws Exception {
        SupportTicketResponseDTO ticket = new SupportTicketResponseDTO();
        ticket.setTicketId(1);
        ticket.setUserId(100);
        ticket.setIssue("Login issue");
        ticket.setStatus(TicketStatus.PENDING);
        ticket.setAssignedAgentId(101);

        Mockito.when(service.getTicketsByAssignedAgentId(101)).thenReturn(List.of(ticket));

        mockMvc.perform(get("/api/support-tickets/agent/101"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.size()", is(1)))
                .andExpect(jsonPath("$[0].assignedAgentId", is(101)));
    }

    @Test
     void testGetAgentTicketsByStatus_Success() throws Exception {
        SupportTicketResponseDTO ticket1 = new SupportTicketResponseDTO();
        ticket1.setTicketId(1);
        ticket1.setAssignedAgentId(101);
        ticket1.setStatus(TicketStatus.PENDING);

        SupportTicketResponseDTO ticket2 = new SupportTicketResponseDTO();
        ticket2.setTicketId(2);
        ticket2.setAssignedAgentId(101);
        ticket2.setStatus(TicketStatus.COMPLETED);

        Mockito.when(service.getTicketsByAssignedAgentId(101)).thenReturn(List.of(ticket1, ticket2));

        mockMvc.perform(get("/api/support-tickets/agent/101/status/PENDING"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.size()", is(1)))
                .andExpect(jsonPath("$[0].status", is("PENDING")));
    }
    @Test
     void testCreateTicket_Success() throws Exception {
        SupportTicketRequestDTO request = new SupportTicketRequestDTO();
        request.setUserId(100);
        request.setIssue("Login issue");

        SupportTicketResponseDTO response = new SupportTicketResponseDTO();
        response.setTicketId(1);
        response.setUserId(100);
        response.setIssue("Login issue");
        response.setStatus(TicketStatus.PENDING);

        Mockito.when(service.createTicket(any())).thenReturn(response);

        mockMvc.perform(post("/api/support-tickets")
                .contentType("application/json")
                .content("""
                    {
                        "userId": 100,
                        "issue": "Login issue"
                    }
                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.ticketId", is(1)))
                .andExpect(jsonPath("$.status", is("PENDING")));
    }

    @Test
     void testAssignAgentAndStatus_Success() throws Exception {
        SupportTicketResponseDTO response = new SupportTicketResponseDTO();
        response.setTicketId(1);
        response.setAssignedAgentId(101);
        response.setStatus(TicketStatus.COMPLETED);

        Mockito.when(service.updateTicketStatusAndAgent(eq(1), eq(SupportTicket.TicketStatus.COMPLETED), eq(101)))
               .thenReturn(response);

        mockMvc.perform(put("/api/support-tickets/1/assign")
                .contentType("application/json")
                .content("""
                    {
                        "assignedAgentId": 101,
                        "status": "COMPLETED"
                    }
                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.assignedAgentId", is(101)))
                .andExpect(jsonPath("$.status", is("COMPLETED")));
    }

    @Test
     void testUpdateStatus_Success() throws Exception {
        SupportTicketResponseDTO response = new SupportTicketResponseDTO();
        response.setTicketId(1);
        response.setStatus(TicketStatus.COMPLETED);

        Mockito.when(service.updateTicketStatus(eq(1), eq(SupportTicket.TicketStatus.COMPLETED)))
               .thenReturn(response);

        mockMvc.perform(put("/api/support-tickets/1/status")
                .contentType("application/json")
                .content("""
                    {
                        "status": "COMPLETED"
                    }
                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("COMPLETED")));
    }
    
    //FAILURE TESTS
    @Test
    void testGetAllTickets_Failure_NoTicketsFound() throws Exception {
        Mockito.when(service.getAllTickets()).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/api/support-tickets"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.size()", is(0)));
    }

    @Test
    void testGetUserTickets_Failure_UserNotFound() throws Exception {
        Mockito.doThrow(new EntityNotFoundException("User", 999))
               .when(service).getTicketsByUserId(999);

        mockMvc.perform(get("/api/support-tickets/user/999"))
                .andExpect(status().isNotFound())
                .andExpect(content().string("User with ID 999 not found."));
    }

    @Test
    void testGetUserTicketsByStatus_Failure_NoMatchingStatus() throws Exception {
        SupportTicketResponseDTO ticket = new SupportTicketResponseDTO();
        ticket.setTicketId(1);
        ticket.setUserId(100);
        ticket.setIssue("Login issue");
        ticket.setStatus(TicketStatus.COMPLETED);

        Mockito.when(service.getTicketsByUserId(100)).thenReturn(List.of(ticket));

        mockMvc.perform(get("/api/support-tickets/user/100/status/PENDING"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.size()", is(0)));
    }

    @Test
    void testGetAgentTickets_Failure_NoTicketsFound() throws Exception {
        Mockito.when(service.getTicketsByAssignedAgentId(999)).thenReturn(Collections.emptyList());

        mockMvc.perform(get("/api/support-tickets/agent/999"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.size()", is(0)));
    }

    @Test
    void testAssignAgentAndStatus_Failure_InvalidTicketId() throws Exception {
        Mockito.when(service.updateTicketStatusAndAgent(eq(999), any(), any()))
               .thenThrow(new EntityNotFoundException("Ticket not found"));

        mockMvc.perform(put("/api/support-tickets/999/assign")
                .contentType("application/json")
                .content("""
                    {
                        "assignedAgentId": 101,
                        "status": "COMPLETED"
                    }
                """))
                .andExpect(status().isNotFound());
    }




}
