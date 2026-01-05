package com.rishan.guardianstack.auth.dto.response;

import com.rishan.guardianstack.auth.model.RefreshToken;

import java.time.Instant;

public record ActiveSessionResponse(
        Long tokenId,
        String deviceName,
        String deviceFingerprint,
        String ipAddress,
        Instant createdAt,
        Instant expiryDate,
        boolean isCurrent
) {
    public static ActiveSessionResponse from(RefreshToken token) {
        return new ActiveSessionResponse(
                token.getId(),
                token.getDeviceName(),
                token.getDeviceFingerprint(),
                token.getIpAddress(),
                token.getCreatedAt(),
                token.getExpiryDate(),
                false // Would need current token to determine this
        );
    }
}