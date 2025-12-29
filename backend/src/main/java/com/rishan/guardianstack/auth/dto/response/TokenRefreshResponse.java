package com.rishan.guardianstack.auth.dto.response;

public record TokenRefreshResponse(
        String accessToken,
        String refreshToken
) {}