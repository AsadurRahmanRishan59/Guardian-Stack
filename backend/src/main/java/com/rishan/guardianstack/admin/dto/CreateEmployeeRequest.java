package com.rishan.guardianstack.admin.dto;

import com.rishan.guardianstack.auth.model.AppRole;
import jakarta.validation.constraints.*;

// ==========================================
// CREATE EMPLOYEE REQUEST
// ==========================================

public record CreateEmployeeRequest(
        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
        String username,

        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        String email,

        @NotNull(message = "Role is required")
        AppRole role,

        @Positive(message = "Contract days must be positive")
        Integer contractDays, // null = use default (365 days)

        String department,

        String position
) {
    // Default constructor will use 365 days if not specified
}





