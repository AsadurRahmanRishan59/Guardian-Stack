package com.rishan.guardianstack.core.exception;

import com.rishan.guardianstack.core.response.ApiErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
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
                "AUTH_FAILURE",
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

    // --- Verification Related Exceptions ---

    @ExceptionHandler(VerificationException.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleVerificationException(VerificationException ex) {
        ApiErrorResponse<Object> response = new ApiErrorResponse<>(
                false,
                ex.getMessage(),
                HttpStatus.BAD_REQUEST.value(),
                "VERIFICATION_ERROR",
                LocalDateTime.now()
        );
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleInvalidTokenException(InvalidTokenException ex) {
        ApiErrorResponse<Object> response = new ApiErrorResponse<>(
                false,
                ex.getMessage(),
                HttpStatus.BAD_REQUEST.value(),
                "INVALID_TOKEN",
                LocalDateTime.now()
        );
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleTokenExpired(TokenExpiredException ex) {
        ApiErrorResponse<Object> response = new ApiErrorResponse<>(
                false,
                "The 6-digit code has expired. Please request a new one.",
                HttpStatus.GONE.value(), // 410 Gone is semantically perfect for expired tokens
                "TOKEN_EXPIRED",
                LocalDateTime.now()
        );
        return new ResponseEntity<>(response, HttpStatus.GONE);
    }

    @ExceptionHandler(TokenAlreadyUsedException.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleTokenAlreadyUsed(TokenAlreadyUsedException ex) {
        ApiErrorResponse<Object> response = new ApiErrorResponse<>(
                false,
                ex.getMessage(),
                HttpStatus.CONFLICT.value(),
                "TOKEN_ALREADY_USED",
                LocalDateTime.now()
        );
        return new ResponseEntity<>(response, HttpStatus.CONFLICT);
    }

    // --- Security Status Exceptions ---

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleDisabledException(DisabledException ex) {
        ApiErrorResponse<Object> response = new ApiErrorResponse<>(
                false,
                "Your account is not verified yet. Please check your email for the OTP.",
                HttpStatus.FORBIDDEN.value(),
                "ACCOUNT_DISABLED",
                LocalDateTime.now()
        );
        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleLockedException(LockedException ex) {
        ApiErrorResponse<Object> response = new ApiErrorResponse<>(
                false,
                "Your account has been locked due to too many failed attempts.",
                HttpStatus.FORBIDDEN.value(),
                "ACCOUNT_LOCKED",
                LocalDateTime.now()
        );
        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
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

// --- Refresh Token Specific Exception ---

    @ExceptionHandler(TokenRefreshException.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleTokenRefreshException(TokenRefreshException ex) {
        log.warn("Refresh token failed: {}", ex.getMessage());

        ApiErrorResponse<Object> response = new ApiErrorResponse<>(
                false,
                ex.getMessage(),
                HttpStatus.FORBIDDEN.value(), // 403 is standard for invalid/expired refresh tokens
                "REFRESH_TOKEN_EXPIRED",      // Specific code for BFF to catch
                LocalDateTime.now()
        );

        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(TokenReusedException.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleTokenReusedException(TokenReusedException ex) {
        log.error("🚨 Token reuse detected: {}", ex.getMessage());
        ApiErrorResponse<Object> response = new ApiErrorResponse<>(
                false,
                ex.getMessage(),
                HttpStatus.UNAUTHORIZED.value(),
                null,
                LocalDateTime.now()
        );

        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<ApiErrorResponse<Object>> handleRateLimitExceededException(RateLimitExceededException ex) {
        log.warn("Rate limit exceeded: {}", ex.getMessage());

        return ResponseEntity
                .status(HttpStatus.TOO_MANY_REQUESTS)
                .body(new ApiErrorResponse<>(
                        false,
                        ex.getMessage(),
                        HttpStatus.TOO_MANY_REQUESTS.value(),
                        null,
                        LocalDateTime.now()
                ));
    }

    // Add these handlers to your GlobalExceptionHandler

    @ExceptionHandler(AccountExpiredException.class)
    public ResponseEntity<ApiErrorResponse<Map<String, Object>>> handleAccountExpiredException(
            AccountExpiredException ex) {
        log.warn("Account expired: {}", ex.getMessage());

        Map<String, Object> details = new HashMap<>();
        details.put("expiredOn", ex.getExpiredOn());
        details.put("message", ex.getMessage());
        details.put("action", "Please contact administrator to renew your account");

        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(new ApiErrorResponse<>(
                        false,
                        ex.getMessage(),
                        HttpStatus.FORBIDDEN.value(),
                        details,
                        LocalDateTime.now()
                ));
    }

    @ExceptionHandler(CredentialsExpiredException.class)
    public ResponseEntity<ApiErrorResponse<Map<String, Object>>> handleCredentialsExpiredException(
            CredentialsExpiredException ex) {
        log.warn("Credentials expired: {}", ex.getMessage());

        Map<String, Object> details = new HashMap<>();
        details.put("expiredOn", ex.getExpiredOn());
        details.put("message", ex.getMessage());
        details.put("action", "Please reset your password to continue");

        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(new ApiErrorResponse<>(
                        false,
                        ex.getMessage(),
                        HttpStatus.FORBIDDEN.value(),
                        details,
                        LocalDateTime.now()
                ));
    }

    @ExceptionHandler(MustChangePasswordException.class)
    public ResponseEntity<ApiErrorResponse<Map<String, Object>>> handleMustChangePasswordException(
            MustChangePasswordException ex) {
        log.info("User must change password: {}", ex.getEmail());

        Map<String, Object> details = new HashMap<>();
        details.put("email", ex.getEmail());
        details.put("message", ex.getMessage());
        details.put("action", "You must change your password before proceeding");

        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(new ApiErrorResponse<>(
                        false,
                        ex.getMessage(),
                        HttpStatus.FORBIDDEN.value(),
                        details,
                        LocalDateTime.now()
                ));
    }
}