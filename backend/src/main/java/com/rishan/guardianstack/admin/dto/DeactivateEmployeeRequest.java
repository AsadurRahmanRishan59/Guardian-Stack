package com.rishan.guardianstack.admin.dto;

// ==========================================
// DEACTIVATE EMPLOYEE REQUEST
// ==========================================

import jakarta.validation.constraints.NotBlank;

public record DeactivateEmployeeRequest(
        @NotBlank(message = "Email is required")
        String email,

        @NotBlank(message = "Reason is required")
        String reason
) {}
