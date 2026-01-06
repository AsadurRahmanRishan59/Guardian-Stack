package com.rishan.guardianstack.masteradmin.user.dto;

import jakarta.validation.constraints.*;
import java.time.LocalDateTime;
import java.util.Set;

public record CreateUserRequestDTO(
        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
        String username,

        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        @Size(max = 100)
        String email,

        @NotBlank(message = "Temporary password is required")
        @Size(min = 8, message = "Password must be at least 8 characters")
        String password,

        @NotEmpty(message = "At least one role must be assigned")
        Set<Integer> roleIds,

        // --- COMPLIANCE & LIFECYCLE ---
        @Future(message = "Account expiry must be in the future")
        LocalDateTime accountExpiryDate, // Useful for contract employees

        @Min(value = 1, message = "Initial password validity must be at least 1 day")
        Integer passwordValidityDays, // Forces rotation after X days

        // --- ADMINISTRATIVE FLAGS ---
        boolean enabled, // Usually true by default for new employees


        boolean mustChangePassword // Security Best Practice: Force change on first login
) {
}