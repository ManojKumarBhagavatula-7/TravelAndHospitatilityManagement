package com.cts.SupportTicket;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import com.cts.SupportTicket.dto.SupportTicketRequestDTO;
import com.cts.SupportTicket.dto.SupportTicketResponseDTO;
import com.cts.SupportTicket.entity.SupportTicket;
import com.cts.SupportTicket.exception.EntityNotFoundException;
import com.cts.SupportTicket.repository.SupportTicketRepository;
import com.cts.SupportTicket.service.SupportTicketServiceImpl;

 class SupportTicketServiceImplTest {

    @Mock
    private SupportTicketRepository repository;

    @InjectMocks
    private SupportTicketServiceImpl service;

    @BeforeEach
     void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
     void testCreateTicket_Success() {
        // Arrange
        SupportTicketRequestDTO requestDTO = new SupportTicketRequestDTO();
        requestDTO.setUserId(123);
        requestDTO.setIssue("Unable to login");
        requestDTO.setAssignedAgentId(null);

        SupportTicket savedTicket = new SupportTicket();
        savedTicket.setTicketId(1);
        savedTicket.setUserId(123);
        savedTicket.setIssue("Unable to login");
        savedTicket.setAssignedAgentId(0);
        savedTicket.setStatus(SupportTicket.TicketStatus.PENDING);
        savedTicket.setCreatedAt(LocalDateTime.now());

        when(repository.save(any(SupportTicket.class))).thenReturn(savedTicket);

        // Act
        SupportTicketResponseDTO responseDTO = service.createTicket(requestDTO);

        // Assert
        assertNotNull(responseDTO);
        assertEquals(1L, responseDTO.getTicketId());
        assertEquals("Unable to login", responseDTO.getIssue());
        assertEquals(123, responseDTO.getUserId());
        assertEquals(SupportTicketResponseDTO.TicketStatus.PENDING, responseDTO.getStatus());

        verify(repository, times(1)).save(any(SupportTicket.class));
    }
    

	private SupportTicket createSampleTicket(int id, int userId) {
		SupportTicket ticket = new SupportTicket();
		ticket.setTicketId(id);
		ticket.setUserId(userId);
		ticket.setIssue("Sample issue");
		ticket.setAssignedAgentId(101);
		ticket.setStatus(SupportTicket.TicketStatus.PENDING);
		ticket.setCreatedAt(LocalDateTime.now());
		return ticket;
	}


    @Test
     void testGetAllTickets_Success() {
	    	List<SupportTicket> tickets = Arrays.asList(
	    	createSampleTicket(1, 100),
	    	createSampleTicket(2, 101)
	    	);
	
			when(repository.findAll()).thenReturn(tickets);
			
			List<SupportTicketResponseDTO> result = service.getAllTickets();
			
			assertEquals(2, result.size());
			verify(repository, times(1)).findAll();
			}
			
			@Test
			 void testGetTicketById_Success() throws EntityNotFoundException {
			SupportTicket ticket = createSampleTicket(1, 100);
			when(repository.findById(1)).thenReturn(Optional.of(ticket));
			
			SupportTicketResponseDTO result = service.getTicketById(1);
			
			assertNotNull(result);
			assertEquals(100, result.getUserId());
			verify(repository, times(1)).findById(1);
		}

	@Test
	 void testGetTicketById_NotFound() {
		when(repository.findById(999)).thenReturn(Optional.empty());
		
		EntityNotFoundException exception = assertThrows(EntityNotFoundException.class, () -> {
		service.getTicketById(999);
		});
		
		assertEquals("Ticket not found with id: 999", exception.getMessage());
		verify(repository, times(1)).findById(999);
		}
		
		@Test
		 void testGetTicketsByUserId_Success() throws EntityNotFoundException {
		List<SupportTicket> tickets = Arrays.asList(
		createSampleTicket(1, 100),
		createSampleTicket(2, 100)
		);
		
		when(repository.findByUserId(100)).thenReturn(tickets);
		
		List<SupportTicketResponseDTO> result = service.getTicketsByUserId(100);
		
		assertEquals(2, result.size());
		verify(repository, times(2)).findByUserId(100); 
	}

	@Test
	 void testGetTicketsByUserId_NotFound() {
		when(repository.findByUserId(999)).thenReturn(List.of());
		
		EntityNotFoundException exception = assertThrows(EntityNotFoundException.class, () -> {
		service.getTicketsByUserId(999);
		});
		
		assertEquals("No Tickets Found for User with ID: 999", exception.getMessage());
		verify(repository, times(1)).findByUserId(999);
	}
	
	@Test
	 void testGetTicketsByAssignedAgentId_Success() throws EntityNotFoundException {
	    List<SupportTicket> tickets = Arrays.asList(
	        createSampleTicket(1, 100),
	        createSampleTicket(2, 101)
	    );

	    when(repository.findByAssignedAgentId(101)).thenReturn(tickets);

	    List<SupportTicketResponseDTO> result = service.getTicketsByAssignedAgentId(101);

	    assertEquals(2, result.size());
	    verify(repository, times(2)).findByAssignedAgentId(101); // Called twice in method
	}

	@Test
	 void testGetTicketsByAssignedAgentId_NotFound() {
	    when(repository.findByAssignedAgentId(999)).thenReturn(List.of());

	    EntityNotFoundException exception = assertThrows(EntityNotFoundException.class, () -> {
	        service.getTicketsByAssignedAgentId(999);
	    });

	    assertEquals("agent not found with ID :999", exception.getMessage());
	    verify(repository, times(1)).findByAssignedAgentId(999);
	}
	
	@Test
	 void testGetTicketsByStatus_Success() {
	    List<SupportTicket> tickets = Arrays.asList(
	        createSampleTicket(1, 100),
	        createSampleTicket(2, 101)
	    );

	    when(repository.findByStatus(SupportTicket.TicketStatus.PENDING)).thenReturn(tickets);

	    List<SupportTicketResponseDTO> result = service.getTicketsByStatus("pending");

	    assertEquals(2, result.size());
	    verify(repository, times(1)).findByStatus(SupportTicket.TicketStatus.PENDING);
	}

	@Test
	 void testGetTicketsByStatus_InvalidStatus() {
	    assertThrows(IllegalArgumentException.class, () -> {
	        service.getTicketsByStatus("invalid_status");
	    });
	}

	@Test
	 void testUpdateTicketStatusAndAgent_Success() throws EntityNotFoundException {
	    SupportTicket ticket = createSampleTicket(1, 100);
	    when(repository.findById(1)).thenReturn(Optional.of(ticket));
	    when(repository.save(any(SupportTicket.class))).thenAnswer(invocation -> invocation.getArgument(0));

	    SupportTicketResponseDTO result = service.updateTicketStatusAndAgent(1, SupportTicket.TicketStatus.COMPLETED, 102);

	    assertNotNull(result);
	    assertEquals(SupportTicketResponseDTO.TicketStatus.COMPLETED, result.getStatus());
	    assertEquals(102, result.getAssignedAgentId());
	    verify(repository, times(1)).findById(1);
	    verify(repository, times(1)).save(any(SupportTicket.class));
	}

	@Test
	 void testUpdateTicketStatusAndAgent_NotFound() {
	    when(repository.findById(999)).thenReturn(Optional.empty());

	    EntityNotFoundException exception = assertThrows(EntityNotFoundException.class, () -> {
	        service.updateTicketStatusAndAgent(999, SupportTicket.TicketStatus.COMPLETED, 102);
	    });

	    assertEquals("Ticket not found with id: 999", exception.getMessage());
	    verify(repository, times(1)).findById(999);
	}

	@Test
	 void testUpdateTicketStatus_Success() throws EntityNotFoundException {
	    SupportTicket ticket = createSampleTicket(1, 100);
	    when(repository.findById(1)).thenReturn(Optional.of(ticket));
	    when(repository.save(any(SupportTicket.class))).thenAnswer(invocation -> invocation.getArgument(0));

	    SupportTicketResponseDTO result = service.updateTicketStatus(1, SupportTicket.TicketStatus.COMPLETED);

	    assertNotNull(result);
	    assertEquals(SupportTicketResponseDTO.TicketStatus.COMPLETED, result.getStatus());
	    verify(repository, times(1)).findById(1);
	    verify(repository, times(1)).save(any(SupportTicket.class));
	}

	@Test
	 void testUpdateTicketStatus_NotFound() {
	    when(repository.findById(999)).thenReturn(Optional.empty());

	    EntityNotFoundException exception = assertThrows(EntityNotFoundException.class, () -> {
	        service.updateTicketStatus(999, SupportTicket.TicketStatus.COMPLETED);
	    });

	    assertEquals("Ticket not found with id: 999", exception.getMessage());
	    verify(repository, times(1)).findById(999);
	}
	@Test
	void testCreateTicket_WithAssignedAgentId() {
	    // Arrange
	    SupportTicketRequestDTO requestDTO = new SupportTicketRequestDTO();
	    requestDTO.setUserId(456);
	    requestDTO.setIssue("App crashes on launch");
	    requestDTO.setAssignedAgentId(101); // Non-null value

	    SupportTicket savedTicket = new SupportTicket();
	    savedTicket.setTicketId(2);
	    savedTicket.setUserId(456);
	    savedTicket.setIssue("App crashes on launch");
	    savedTicket.setAssignedAgentId(101);
	    savedTicket.setStatus(SupportTicket.TicketStatus.PENDING);
	    savedTicket.setCreatedAt(LocalDateTime.now());

	    when(repository.save(any(SupportTicket.class))).thenReturn(savedTicket);

	    // Act
	    SupportTicketResponseDTO responseDTO = service.createTicket(requestDTO);

	    // Assert
	    assertNotNull(responseDTO);
	    assertEquals(2L, responseDTO.getTicketId());
	    assertEquals(456, responseDTO.getUserId());
	    assertEquals("App crashes on launch", responseDTO.getIssue());
	    assertEquals(101, responseDTO.getAssignedAgentId());
	    assertEquals(SupportTicketResponseDTO.TicketStatus.PENDING, responseDTO.getStatus());

	    verify(repository, times(1)).save(any(SupportTicket.class));
	}



	
}
