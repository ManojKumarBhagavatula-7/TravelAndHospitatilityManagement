package com.cts.booking.service.impl;
 
import com.cts.booking.dto.BookingDto;
import com.cts.booking.dto.BookingResponseDto;
import com.cts.booking.entity.Booking;
import com.cts.booking.exception.*;
import com.cts.booking.repository.BookingRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.modelmapper.ModelMapper;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.*;
 
import java.util.List;
import java.util.Optional;
 
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
 
@ExtendWith(MockitoExtension.class)

public class BookingServiceImplTest {
 
    @Mock
    private BookingRepository bookingRepo;
 
    @Mock
    private ModelMapper modelMapper;
 
    @InjectMocks
    private BookingServiceImpl bookingService;
 
    private Booking booking;
    private BookingDto bookingDto;
 
    @BeforeEach
    void setUp() {
        booking = new Booking(1L, 100L, "FLIGHT", 10L, 20L, 30L, "CONFIRMED", 200L);
        bookingDto = new BookingDto(1L, 100L, "FLIGHT", 10L, 20L, 30L, "CONFIRMED", 200L);
    }
 
    // createBooking()
    @Test
    void testCreateBooking_Success() {
        when(modelMapper.map(bookingDto, Booking.class)).thenReturn(booking);
        when(bookingRepo.save(booking)).thenReturn(booking);
        when(modelMapper.map(booking, BookingDto.class)).thenReturn(bookingDto);
 
        BookingDto saved = bookingService.createBooking(bookingDto);
        assertThat(saved).isNotNull();
        assertThat(saved.getBookingId()).isEqualTo(1L);
    }
 
    @Test
    void testCreateBooking_ConflictException() {
        when(modelMapper.map(bookingDto, Booking.class)).thenReturn(booking);
        when(bookingRepo.save(booking)).thenThrow(new DataIntegrityViolationException("Duplicate"));
 
        assertThatThrownBy(() -> bookingService.createBooking(bookingDto))
                .isInstanceOf(DataIntegrityViolationException.class);
    }
 
    @Test
    void testCreateBooking_InternalServerError() {
        when(modelMapper.map(bookingDto, Booking.class)).thenThrow(new RuntimeException("Mapper failed"));
 
        assertThatThrownBy(() -> bookingService.createBooking(bookingDto))
                .isInstanceOf(RuntimeException.class);
    }
 
    //  getAllBookings()
    @Test
    void testGetAllBookings() {
        Page<Booking> page = new PageImpl<>(List.of(booking));
        when(bookingRepo.findAll(any(Pageable.class))).thenReturn(page);
        when(modelMapper.map(any(Booking.class), eq(BookingDto.class))).thenReturn(bookingDto);
 
        BookingResponseDto response = bookingService.getAllBookings(0, 5, "bookingId", "asc");
 
        assertThat(response).isNotNull();
        assertThat(response.getContent()).hasSize(1);
    }
 
    //  getBookingDetailsById()
    @Test
    void testGetBookingDetailsById_Success() {
        when(bookingRepo.findById(1L)).thenReturn(Optional.of(booking));
        when(modelMapper.map(booking, BookingDto.class)).thenReturn(bookingDto);
 
        BookingDto result = bookingService.getBookingDetailsById(1L);
        assertThat(result).isNotNull();
    }
 
    @Test
    void testGetBookingDetailsById_NotFound() {
        when(bookingRepo.findById(99L)).thenReturn(Optional.empty());
 
        assertThatThrownBy(() -> bookingService.getBookingDetailsById(99L))
                .isInstanceOf(ResourceNotFoundException.class);
    }
 
    @Test
    void testGetBookingDetailsById_Unauthorized() {
        when(bookingRepo.findById(1L)).thenThrow(new UnauthorizedException("Unauthorized"));
 
        assertThatThrownBy(() -> bookingService.getBookingDetailsById(1L))
                .isInstanceOf(UnauthorizedException.class);
    }
 
    @Test
    void testGetBookingDetailsById_Forbidden() {
        when(bookingRepo.findById(1L)).thenThrow(new ForbiddenException("Forbidden"));
 
        assertThatThrownBy(() -> bookingService.getBookingDetailsById(1L))
                .isInstanceOf(ForbiddenException.class);
    }
 
    @Test
    void testGetBookingDetailsById_BadRequest() {
        when(bookingRepo.findById(1L)).thenThrow(new BadRequestException("Bad Request"));
 
        assertThatThrownBy(() -> bookingService.getBookingDetailsById(1L))
                .isInstanceOf(BadRequestException.class);
    }
 
    //  updatePackageById()
    @Test
    void testUpdatePackageById_Success() {
        when(bookingRepo.findById(1L)).thenReturn(Optional.of(booking));
        when(bookingRepo.save(any())).thenReturn(booking);
        when(modelMapper.map(booking, BookingDto.class)).thenReturn(bookingDto);
 
        BookingDto updated = bookingService.updatePackageById(1L, bookingDto);
        assertThat(updated.getStatus()).isEqualTo("CONFIRMED");
    }
 
    @Test
    void testUpdatePackageById_NotFound() {
        when(bookingRepo.findById(1L)).thenReturn(Optional.empty());
 
        assertThatThrownBy(() -> bookingService.updatePackageById(1L, bookingDto))
                .isInstanceOf(ResourceNotFoundException.class);
    }
 
    @Test
    void testUpdatePackageById_InternalServerError() {
        when(bookingRepo.findById(1L)).thenThrow(new InternalServerErrorException("DB Error"));
 
        assertThatThrownBy(() -> bookingService.updatePackageById(1L, bookingDto))
                .isInstanceOf(InternalServerErrorException.class);
    }
 
    //  getBookingsByUserId()
    @Test
    void testGetBookingsByUserId() {
        Page<Booking> page = new PageImpl<>(List.of(booking));
        when(bookingRepo.findByUserId(eq(100L), any(Pageable.class))).thenReturn(page);
        when(modelMapper.map(any(), eq(BookingDto.class))).thenReturn(bookingDto);
 
        BookingResponseDto response = bookingService.getBookingsByUserId(100L, 0, 5, "bookingId", "asc");
        assertThat(response.getContent()).hasSize(1);
    }
 
    // ✅ getBookingsByType()
    @Test
    void testGetBookingsByType() {
        Page<Booking> page = new PageImpl<>(List.of(booking));
        when(bookingRepo.findByTypeIgnoreCase(eq("FLIGHT"), any(Pageable.class))).thenReturn(page);
        when(modelMapper.map(any(), eq(BookingDto.class))).thenReturn(bookingDto);
 
        BookingResponseDto response = bookingService.getBookingsByType("FLIGHT", 0, 5, "type", "asc");
        assertThat(response.getContent()).hasSize(1);
    }
 
    //  getBookingsByStatus()
    @Test
    void testGetBookingsByStatus() {
        Page<Booking> page = new PageImpl<>(List.of(booking));
        when(bookingRepo.findByStatusIgnoreCase(eq("CONFIRMED"), any(Pageable.class))).thenReturn(page);
        when(modelMapper.map(any(), eq(BookingDto.class))).thenReturn(bookingDto);
 
        BookingResponseDto response = bookingService.getBookingsByStatus("CONFIRMED", 0, 5, "status", "asc");
        assertThat(response.getContent()).hasSize(1);
    }
 
    @Test
    void testGetBookingsByStatus_InternalServerError() {
        when(bookingRepo.findByStatusIgnoreCase(eq("CONFIRMED"), any(Pageable.class)))
                .thenThrow(new InternalServerErrorException("Internal error"));
 
        assertThatThrownBy(() -> bookingService.getBookingsByStatus("CONFIRMED", 0, 5, "status", "asc"))
                .isInstanceOf(InternalServerErrorException.class);
    }
 
    //  getActiveBookings()
    @Test
    void testGetActiveBookings() {
        Page<Booking> page = new PageImpl<>(List.of(booking));
        when(bookingRepo.findByStatusIgnoreCaseIn(eq(List.of("CONFIRMED", "IN_PROGRESS")), any(Pageable.class)))
                .thenReturn(page);
        when(modelMapper.map(any(), eq(BookingDto.class))).thenReturn(bookingDto);
 
        BookingResponseDto response = bookingService.getActiveBookings(0, 5, "status", "asc");
        assertThat(response.getContent()).hasSize(1);
    }
}
 