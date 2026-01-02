package com.rishan.guardianstack.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record SignUpRequestDTO(
        @NotBlank(message = "Official full name is required")
        @Size(min = 3, max = 255, message = "Name must be between 3–255 characters")
        @Pattern(
                regexp = "^[a-zA-Z\\s.]+$",
                message = "Name can only contain letters, spaces, and dots (e.g., Md. Karim)"
        )
        String username,

        @Email(message = "Invalid email format")
        @Size(max = 50, message = "Email must not exceed 50 characters")
        String email,

        @NotBlank(message = "Password is required")
        String password
) {
}