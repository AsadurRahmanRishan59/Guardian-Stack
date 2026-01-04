package com.rishan.guardianstack.auth.service.impl;

import com.rishan.guardianstack.auth.model.RefreshToken;
import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.auth.repository.RefreshTokenRepository;
import com.rishan.guardianstack.auth.repository.UserRepository;
import com.rishan.guardianstack.auth.service.AuditService;
import com.rishan.guardianstack.auth.service.RefreshTokenService;
import com.rishan.guardianstack.core.exception.InvalidTokenException;
import com.rishan.guardianstack.core.exception.ResourceNotFoundException;
import com.rishan.guardianstack.core.exception.TokenExpiredException;
import com.rishan.guardianstack.core.exception.TokenReusedException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;


@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final AuditService auditService;

    @Value("${app.security.jwt.refresh-token.expiration}")
    private Long refreshTokenDurationMs;

    /**
     * Creates a new refresh token with device information
     */
    @Override
    @Transactional
    public RefreshToken createRefreshToken(String email, HttpServletRequest request) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Single session policy: delete old tokens
        refreshTokenRepository.deleteByUser(user);
        refreshTokenRepository.flush();

        String deviceFingerprint = generateDeviceFingerprint(request);
        String deviceName = parseDeviceName(request.getHeader("User-Agent"));

        RefreshToken refreshToken = RefreshToken.builder().user(user).token(UUID.randomUUID().toString()).expiryDate(Instant.now().plusMillis(refreshTokenDurationMs)).createdAt(Instant.now()).revoked(false).ipAddress(auditService.getClientIp(request)).userAgent(request.getHeader("User-Agent")).deviceFingerprint(deviceFingerprint).deviceName(deviceName).build();

        RefreshToken saved = refreshTokenRepository.save(refreshToken);
        log.info("✓ Created new refresh token for user: {} from device: {}", email, deviceName);
        return saved;
    }

    /**
     * Rotates refresh token (creates new, revokes old) with reuse detection
     */
    @Override
    @Transactional
    public RefreshToken rotateRefreshToken(String oldTokenString, User user, HttpServletRequest request) {
        RefreshToken oldToken = refreshTokenRepository.findByToken(oldTokenString).orElseThrow(() -> new InvalidTokenException("Refresh token not found"));

        // CRITICAL: Reuse Detection
        if (oldToken.isRevoked()) {
            log.error("🚨 SECURITY ALERT: Token reuse detected for user: {}", user.getEmail());
            log.error("   Token ID: {}, Created: {}, Revoked: {}", oldToken.getId(), oldToken.getCreatedAt(), oldToken.getRevokedAt());

            // Nuclear option: Revoke ALL tokens for this user
            int deletedCount = refreshTokenRepository.deleteByUser(user);
            log.error("   Revoked {} tokens for security", deletedCount);

            // Log security incident
            auditService.logFailedEvent("REFRESH_TOKEN_REUSE_DETECTED", user.getEmail(), "Attempted to reuse already-rotated refresh token - possible token theft", auditService.getClientIp(request), auditService.getUserAgent(request));

            throw new TokenReusedException("This refresh token has already been used. " + "For your security, all sessions have been terminated. " + "Please login again.");
        }

        // Mark old token as revoked (keep for audit trail)
        oldToken.setRevoked(true);
        oldToken.setRevokedAt(Instant.now());

        // Create new token with device info
        String deviceFingerprint = generateDeviceFingerprint(request);
        String deviceName = parseDeviceName(request.getHeader("User-Agent"));

        RefreshToken newToken = RefreshToken.builder().user(user).token(UUID.randomUUID().toString()).expiryDate(Instant.now().plusMillis(refreshTokenDurationMs)).createdAt(Instant.now()).revoked(false).ipAddress(auditService.getClientIp(request)).userAgent(request.getHeader("User-Agent")).deviceFingerprint(deviceFingerprint).deviceName(deviceName).build();

        // Link tokens (token family/chain)
        oldToken.setReplacedByToken(newToken.getToken());

        // Save both
        refreshTokenRepository.save(oldToken);
        RefreshToken saved = refreshTokenRepository.save(newToken);

        log.info("✓ Rotated refresh token for user: {} (Old: {}... → New: {}...)", user.getEmail(), oldTokenString.substring(0, 8), saved.getToken().substring(0, 8));

        return saved;
    }

    @Override
    public RefreshToken verifyExpiration(RefreshToken token) {

        if (token.isRevoked()) {
            log.warn("Attempted to use revoked token for user: {}", token.getUser().getEmail());

            // Delete all tokens for this user (security measure)
            refreshTokenRepository.deleteByUser(token.getUser());

            throw new TokenReusedException(
                    "This refresh token was already used. " +
                            "All sessions have been terminated for security."
            );
        }

        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            log.warn("Expired refresh token deleted for user: {}", token.getUser().getEmail());
            throw new TokenExpiredException("Refresh token has expired. Please sign in again.");
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
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token).orElseThrow(() -> new InvalidTokenException("Refresh token not found"));

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
        User user = userRepository.findByEmail(email).orElseThrow(() -> new ResourceNotFoundException("User not found"));
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

    /**
     * Cleanup old revoked tokens (keep for 30 days audit trail)
     */
    @Scheduled(cron = "${app.security.token-cleanup.cron:0 0 3 * * ?}")
    @Transactional
    public void scheduledRevokedTokenCleanup() {
        Instant cutoff = Instant.now().minusSeconds(30 * 24 * 60 * 60); // 30 days
        int deleted = refreshTokenRepository.deleteRevokedTokensOlderThan(cutoff);
        log.info("Cleaned up {} old revoked tokens (audit trail retention)", deleted);
    }

    /**
     * Generates device fingerprint from request
     */
    private String generateDeviceFingerprint(HttpServletRequest request) {
        try {
            String data = String.format("%s|%s", auditService.getClientIp(request), request.getHeader("User-Agent"));

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            log.warn("Failed to generate device fingerprint", e);
            return "unknown";
        }
    }

    /**
     * Parses user agent to extract device name
     */
    private String parseDeviceName(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return "Unknown Device";
        }

        // Simple parsing (you can use a library like UADetector for better results)
        if (userAgent.contains("Windows")) {
            return "Windows PC";
        } else if (userAgent.contains("Mac")) {
            return "Mac";
        } else if (userAgent.contains("iPhone")) {
            return "iPhone";
        } else if (userAgent.contains("iPad")) {
            return "iPad";
        } else if (userAgent.contains("Android")) {
            return "Android Device";
        } else if (userAgent.contains("Linux")) {
            return "Linux PC";
        }

        return "Unknown Device";
    }
}