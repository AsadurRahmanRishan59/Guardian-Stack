package com.rishan.guardianstack.auth.service.impl;

import com.rishan.guardianstack.auth.model.RefreshToken;
import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.auth.repository.RefreshTokenRepository;
import com.rishan.guardianstack.auth.repository.UserRepository;
import com.rishan.guardianstack.auth.service.RefreshTokenService;
import com.rishan.guardianstack.core.exception.InvalidTokenException;
import com.rishan.guardianstack.core.exception.ResourceNotFoundException;
import com.rishan.guardianstack.core.exception.TokenExpiredException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;


@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    @Value("${app.security.jwt.refresh-token.expiration}")
    private Long refreshTokenDurationMs;

    @Override
    @Transactional
    public RefreshToken createRefreshToken(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Single session policy: delete old tokens
        refreshTokenRepository.deleteByUser(user);
        refreshTokenRepository.flush();

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .createdAt(Instant.now())
                .revoked(false)
                .build();

        RefreshToken saved = refreshTokenRepository.save(refreshToken);
        log.info("Created new refresh token for user: {}", email);
        return saved;
    }

    @Override
    public RefreshToken verifyExpiration(RefreshToken token) {

        if (token.isRevoked()) {
            log.warn("Attempted to use revoked token for user: {}",
                    token.getUser().getEmail());
            throw new TokenExpiredException(
                    "Refresh token has been revoked. Please sign in again."
            );
        }

        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            log.warn("Expired refresh token deleted for user: {}",
                    token.getUser().getEmail());
            throw new TokenExpiredException(
                    "Refresh token has expired. Please sign in again."
            );
        }
        return token;
    }

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Override
    @Transactional
    public void revokeToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new InvalidTokenException("Refresh token not found"));

        refreshTokenRepository.delete(refreshToken);
        log.info("Revoked refresh token for user: {}", refreshToken.getUser().getEmail());
    }

    @Override
    @Transactional
    public void revokeAllUserTokens(User user) {
        int deleted = refreshTokenRepository.deleteByUser(user);
        log.info("Revoked {} refresh token(s) for user: {}", deleted, user.getEmail());
    }

    @Override
    @Transactional
    public void revokeAllUserTokens(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        revokeAllUserTokens(user);
    }

    @Override
    @Transactional
    public int cleanupExpiredTokens() {
        Instant now = Instant.now();
        int deleted = refreshTokenRepository.deleteByExpiryDateBefore(now);
        log.info("Cleaned up {} expired refresh tokens", deleted);
        return deleted;
    }

    /**
     * Scheduled job to clean up expired tokens daily at 3 AM
     */
    @Scheduled(cron = "${app.security.token-cleanup.cron:0 0 3 * * ?}")
    @Transactional
    public void scheduledCleanup() {
        log.info("Starting scheduled cleanup of expired refresh tokens");
        cleanupExpiredTokens();
    }
}