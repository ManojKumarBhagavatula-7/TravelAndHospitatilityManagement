package com.cts.authentication.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * A generic wrapper class for standardizing API responses across the application.
 * It provides a consistent structure for success and error responses,
 * including HTTP status, an optional data payload, and a timestamp for context.
 *
 * @param <T> The type of the data payload contained within the response.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RestResponse<T> {
    /**
     * The HTTP status code of the response (e.g., 200 for OK, 201 for Created, 400 for Bad Request).
     */
    private int status;

    /**
     * The actual data payload returned by the API, if any.
     * This field is null for operations that return no specific data.
     * For error responses, this might contain a map of error details.
     */
    private T data;

    /**
     * The timestamp indicating when the response was generated, in ISO-8601 format.
     */
    private LocalDateTime timestamp;

    /**
     * Static factory method to create a successful {@code RestResponse}.
     *
     * @param status The HTTP status code for the success response.
     * @param data   The actual data payload to be returned. Can be {@code null} if no specific data is returned.
     * @param <T>    The type of the data payload.
     * @return A new {@code RestResponse} instance representing a successful operation.
     */
    public static <T> RestResponse<T> success(int status, T data) {
        return RestResponse.<T>builder()
                .status(status)
                .data(data)
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Static factory method to create an error {@code RestResponse}.
     * The data payload for error responses typically contains error details.
     *
     * @param status The HTTP status code for the error response.
     * @param data   The actual error details payload to be returned (e.g., a Map with error messages). Can be {@code null}.
     * @param <T>    The type of the data payload.
     * @return A new {@code RestResponse} instance representing an error condition.
     */
    public static <T> RestResponse<T> error(int status, T data) {
        return RestResponse.<T>builder()
                .status(status)
                .data(data) // For errors, 'data' will contain the error details map
                .timestamp(LocalDateTime.now())
                .build();
    }
}