package com.rishan.guardianstack.core.exception;

import com.rishan.digitalinsurance.core.response.ApiErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleBadCredentials(BadCredentialsException ex) {
        ApiErrorResponse<Object> response = new ApiErrorResponse<>(
                false,
                ex.getMessage(),
                HttpStatus.UNAUTHORIZED.value(),
                null,
                LocalDateTime.now()
        );
        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(UserDetailsNotFoundException.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleUserDetailsNotFound(UserDetailsNotFoundException ex) {
        ApiErrorResponse<Object> response = new ApiErrorResponse<>(
                false,
                ex.getMessage(),
                HttpStatus.NOT_FOUND.value(),
                null,
                LocalDateTime.now()
        );
        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(JwtGenerationException.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleJwtGenerationException(JwtGenerationException ex) {
        ApiErrorResponse<Object> response = new ApiErrorResponse<>(
                false,
                ex.getMessage(),
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                null,
                LocalDateTime.now()
        );
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // Resource Not Found
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleResourceNotFoundException(ResourceNotFoundException ex) {
        log.error("Resource not found: {}", ex.getMessage());

        Object errors = ex.getFieldName() != null
                ? Map.of(ex.getFieldName(), ex.getMessage())
                : null;

        ApiErrorResponse<Object> response = new ApiErrorResponse<>(
                false,
                ex.getMessage(),
                HttpStatus.NOT_FOUND.value(),
                errors,
                LocalDateTime.now());

        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(DuplicateResourceException.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleDuplicateResourceException(DuplicateResourceException ex) {
        Map<String, String> data = Map.of(ex.getField(), ex.getMessage());
        ApiErrorResponse<Object> response = new ApiErrorResponse<>(
                false,
                "A resource with the same value already exists.",
                HttpStatus.CONFLICT.value(),
                data,
                LocalDateTime.now());
        return new ResponseEntity<>(response, HttpStatus.CONFLICT);
    }

    // File Access Exception
    @ExceptionHandler(FileAccessException.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleFileAccessException(FileAccessException ex) {
        log.error("File access error: {}", ex.getMessage());

        ApiErrorResponse<Object> response = new ApiErrorResponse<>(
                false,
                ex.getMessage(),
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                null,
                LocalDateTime.now()
        );

        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleValidationExceptions(MethodArgumentNotValidException ex) {

        Map<String, String> errors = new HashMap<>();

        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName;
            if (error instanceof FieldError fieldError) {
                fieldName = fieldError.getField();
            } else {
                fieldName = error.getObjectName(); // fallback for non-field errors
            }

            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        ApiErrorResponse<Object> response = new ApiErrorResponse<>(
                false,
                "Validation failed",
                HttpStatus.BAD_REQUEST.value(),
                errors,
                LocalDateTime.now()
        );

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    // Multiple Field Validation Errors
    @ExceptionHandler(MultipleFieldValidationException.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleMultipleFieldValidation(MultipleFieldValidationException ex) {
        ApiErrorResponse<Object> response = new ApiErrorResponse<>(
                false,
                "Multiple unique constraint violations found",
                HttpStatus.CONFLICT.value(),
                ex.getFieldErrors(),
                LocalDateTime.now());
        return new ResponseEntity<>(response, HttpStatus.CONFLICT);
    }

    // Optional fallback for any unexpected exceptions
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleAllExceptions(Exception ex) {
        log.error("Unexpected error occurred", ex);

        ApiErrorResponse<Object> response = new ApiErrorResponse<>(
                false,
                "Internal server error",
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                null,
                LocalDateTime.now()
        );
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}