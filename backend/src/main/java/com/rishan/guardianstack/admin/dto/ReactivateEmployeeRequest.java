package com.rishan.guardianstack.admin.dto;

// ==========================================
// REACTIVATE EMPLOYEE REQUEST
// ==========================================

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

public record ReactivateEmployeeRequest(
        @NotBlank(message = "Email is required")
        String email,

        @NotNull(message = "Contract days is required")
        @Positive(message = "Contract days must be positive")
        Integer contractDays
) {}