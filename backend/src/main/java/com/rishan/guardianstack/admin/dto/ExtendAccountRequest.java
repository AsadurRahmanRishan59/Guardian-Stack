package com.rishan.guardianstack.admin.dto;

// ==========================================
// EXTEND ACCOUNT REQUEST
// ==========================================

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

public record ExtendAccountRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        String email,

        @NotNull(message = "Additional days is required")
        @Positive(message = "Additional days must be positive")
        Integer additionalDays,

        String reason
) {}