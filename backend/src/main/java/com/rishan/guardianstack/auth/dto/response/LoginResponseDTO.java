package com.rishan.guardianstack.auth.dto.response;

public record LoginResponseDTO(
        String jwtToken,
        UserResponse userResponse) {
}
