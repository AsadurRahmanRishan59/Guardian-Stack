package com.rishan.guardianstack.auth.dto.request;

import jakarta.validation.constraints.Pattern;

public record LoginRequestDTO(
        @Pattern(
                regexp = "^(?=.{3,20}$)(?!.*__)[a-zA-Z0-9]+(_[a-zA-Z0-9]+)*$",
                message = "Username must be 3-20 characters, letters/numbers/underscore only, cannot start or end with underscore"
        )
        String username,

        @Pattern(
                regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()\\-_=+]).{8,120}$",
                message = "Password must be 8-120 chars, include uppercase, lowercase, number, and special char, no spaces"
        )
        String password

) {
}
