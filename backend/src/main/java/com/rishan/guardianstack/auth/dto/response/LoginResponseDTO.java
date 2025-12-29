package com.rishan.guardianstack.auth.dto.response;

public record LoginResponseDTO(
        String jwtToken,
        String refreshToken,
        UserResponse userResponse) {
}
