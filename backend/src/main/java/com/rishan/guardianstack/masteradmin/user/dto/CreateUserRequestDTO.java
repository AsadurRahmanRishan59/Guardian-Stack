package com.rishan.guardianstack.masteradmin.user.dto;

import jakarta.validation.constraints.*;
import java.time.LocalDate;
import java.util.List;

public record CreateUserRequestDTO(
        @NotBlank(message = "Official full name is required")
        @Size(min = 3, max = 255, message = "Name must be between 3–255 characters")
        @Pattern(
                regexp = "^[a-zA-Z\\s.]+$",
                message = "Name can only contain letters, spaces, and dots (e.g., Md. Karim)"
        )
        String username,

        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        @Size(max = 50, message = "Email must not exceed 50 characters")
        String email,

        @NotBlank(message = "Password is required")
        @Size(min = 8, message = "Password must be at least 8 characters long")
        String password,

        // Security Status Flags
        boolean accountNonLocked,
        boolean accountNonExpired,
        boolean credentialsNonExpired,
        boolean enabled,

        // Date-based policies (Master Admin can set expiry for temporary staff/contractors)
        @FutureOrPresent(message = "Credentials expiry date must be in the present or future")
        LocalDate credentialsExpiryDate,

        @FutureOrPresent(message = "Account expiry date must be in the present or future")
        LocalDate accountExpiryDate,

        @NotEmpty(message = "At least one role must be assigned")
        List<@NotNull(message = "Role ID cannot be null") Integer> roleIds
) {
}