package com.rishan.guardianstack.auth.dto.response;

import java.util.List;

public record LoginResponseDTO(
        String jwtToken,
        String refreshToken,
        List<String> warnings,
        UserResponse userResponse) {
}
