package com.rishan.guardianstack.auth.dto.response;

import java.util.List;

public record UserResponse(
        Long userId,
        String username,
        String email,
        boolean enabled,
        List<String> roles
) {
}
