package com.rishan.guardianstack.auth.controller;

import com.rishan.guardianstack.auth.dto.response.ActiveSessionResponse;
import com.rishan.guardianstack.auth.model.RefreshToken;
import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.auth.repository.RefreshTokenRepository;
import com.rishan.guardianstack.auth.repository.UserRepository;
import com.rishan.guardianstack.auth.service.RefreshTokenService;
import com.rishan.guardianstack.core.exception.ResourceNotFoundException;
import com.rishan.guardianstack.core.response.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/auth/sessions")
@RequiredArgsConstructor
public class SessionManagementController {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;

    /**
     * Get all active sessions (devices) for current user
     */
    @GetMapping
    public ResponseEntity<ApiResponse<List<ActiveSessionResponse>>> getActiveSessions(
            @AuthenticationPrincipal UserDetails userDetails) {

        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        List<ActiveSessionResponse> sessions = refreshTokenRepository
                .findActiveDevicesByUser(user, Instant.now())
                .stream()
                .map(ActiveSessionResponse::from)
                .toList();

        return ResponseEntity.ok(new ApiResponse<>(
                true,
                String.format("Found %d active session(s)", sessions.size()),
                sessions,
                LocalDateTime.now()
        ));
    }

    /**
     * Revoke a specific session (device)
     */
    @DeleteMapping("/{tokenId}")
    public ResponseEntity<ApiResponse<Void>> revokeSession(
            @PathVariable Long tokenId,
            @AuthenticationPrincipal UserDetails userDetails) {

        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        RefreshToken token = refreshTokenRepository.findById(tokenId)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found"));

        // Verify token belongs to current user
        if (!token.getUser().getUserId().equals(user.getUserId())) {
            throw new IllegalArgumentException("Session does not belong to you");
        }

        refreshTokenRepository.delete(token);

        return ResponseEntity.ok(new ApiResponse<>(
                true,
                String.format("Session on %s revoked successfully", token.getDeviceName()),
                null,
                LocalDateTime.now()
        ));
    }

    /**
     * Revoke all other sessions (keep current)
     */
    @DeleteMapping("/revoke-others")
    public ResponseEntity<ApiResponse<Void>> revokeOtherSessions(
            @RequestParam String currentToken,
            @AuthenticationPrincipal UserDetails userDetails) {

        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Get all active tokens
        List<RefreshToken> allTokens = refreshTokenRepository
                .findActiveDevicesByUser(user, Instant.now());

        // Delete all except current
        int deleted = 0;
        for (RefreshToken token : allTokens) {
            if (!token.getToken().equals(currentToken)) {
                refreshTokenRepository.delete(token);
                deleted++;
            }
        }

        return ResponseEntity.ok(new ApiResponse<>(
                true,
                String.format("Revoked %d other session(s)", deleted),
                null,
                LocalDateTime.now()
        ));
    }
}