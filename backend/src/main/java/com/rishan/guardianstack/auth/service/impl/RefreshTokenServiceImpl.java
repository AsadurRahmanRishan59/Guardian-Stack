package com.rishan.guardianstack.auth.service.impl;

import com.rishan.guardianstack.auth.model.AppRole;
import com.rishan.guardianstack.auth.model.RefreshToken;
import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.auth.repository.RefreshTokenRepository;
import com.rishan.guardianstack.auth.repository.UserRepository;
import com.rishan.guardianstack.auth.service.ELKAuditService;
import com.rishan.guardianstack.auth.service.RefreshTokenService;
import com.rishan.guardianstack.core.exception.InvalidTokenException;
import com.rishan.guardianstack.core.exception.ResourceNotFoundException;
import com.rishan.guardianstack.core.exception.TokenExpiredException;
import com.rishan.guardianstack.core.exception.TokenReusedException;
import com.rishan.guardianstack.core.logging.AuditEventType;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final ELKAuditService elkAuditService;

    @Value("${app.security.jwt.refresh-token.expiration}")
    private Long refreshTokenDurationMs;

    @Value("${app.security.multi-device.master-admin.enabled}")
    private boolean masterAdminMultiDevice;

    @Value("${app.security.multi-device.admin.max-devices}")
    private int adminMaxDevices;

    @Value("${app.security.multi-device.employee.max-devices}")
    private int employeeMaxDevices;

    @Value("${app.security.multi-device.customer.max-devices}")
    private int customerMaxDevices;

    @Override
    @Transactional(isolation = Isolation.SERIALIZABLE)
    public RefreshToken createRefreshToken(String email, HttpServletRequest request) {

        User user = userRepository.findByEmailForUpdate(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        DevicePolicy policy = getDevicePolicyForUser(user);

        if (policy.multiDeviceEnabled()) {
            return createRefreshTokenMultiDevice(user, request, policy.maxDevices());
        } else {
            return createRefreshTokenSingleDevice(user, request);
        }
    }

    private RefreshToken createRefreshTokenSingleDevice(User user, HttpServletRequest request) {
        int deleted = refreshTokenRepository.deleteByUser(user);
        if (deleted > 0) {
            // BUFFERED - Only logged if deletion succeeds
            elkAuditService.logSuccess(
                    AuditEventType.DEVICE_SESSION_REPLACED,
                    user,
                    "Previous device session terminated (Single device policy)"
            );
        }
        refreshTokenRepository.flush();
        return buildAndSaveToken(user, request);
    }

    private RefreshToken createRefreshTokenMultiDevice(User user, HttpServletRequest request, int maxDevices) {
        String deviceFingerprint = generateDeviceFingerprint(request);

        Optional<RefreshToken> existingDeviceToken =
                refreshTokenRepository.findByUserAndDeviceFingerprint(user, deviceFingerprint);

        if (existingDeviceToken.isPresent()) {
            refreshTokenRepository.delete(existingDeviceToken.get());
            refreshTokenRepository.flush();
        } else {
            long activeDevices = refreshTokenRepository.countActiveTokensByUserForUpdate(user, Instant.now());

            if (activeDevices >= maxDevices) {
                removeOldestToken(user);
                // BUFFERED - Only logged if removal succeeds
                elkAuditService.logSuccess(
                        AuditEventType.DEVICE_LIMIT_REACHED,
                        user,
                        String.format("Limit (%d) reached, oldest device removed", maxDevices)
                );
            }
        }
        return buildAndSaveToken(user, request);
    }

    private RefreshToken buildAndSaveToken(User user, HttpServletRequest request) {
        String deviceFingerprint = generateDeviceFingerprint(request);
        String deviceName = parseDeviceName(request != null ? request.getHeader("User-Agent") : null);
        String ipAddress = request != null ? elkAuditService.getClientIp(request) : "unknown";
        String userAgent = request != null ? request.getHeader("User-Agent") : "unknown";

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .createdAt(Instant.now())
                .revoked(false)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .deviceFingerprint(deviceFingerprint)
                .deviceName(deviceName)
                .build();

        RefreshToken saved = refreshTokenRepository.save(refreshToken);

        // BUFFERED - Only logged if token save succeeds
        elkAuditService.logSuccess(
                AuditEventType.TOKEN_CREATED,
                user,
                String.format("Session created on %s (IP: %s)", deviceName, ipAddress)
        );

        return saved;
    }

    private DevicePolicy getDevicePolicyForUser(User user) {
        if (user.hasRole(AppRole.ROLE_MASTER_ADMIN)) {
            return new DevicePolicy(false, 1, "MASTER_ADMIN");
        }

        if (user.hasRole(AppRole.ROLE_ADMIN)) {
            return new DevicePolicy(true, adminMaxDevices, "ADMIN");
        }

        if (user.hasRole(AppRole.ROLE_EMPLOYEE)) {
            return new DevicePolicy(true, employeeMaxDevices, "EMPLOYEE");
        }

        return new DevicePolicy(true, customerMaxDevices, "CUSTOMER");
    }

    @Override
    @Transactional
    public RefreshToken rotateRefreshToken(String oldTokenString, User user, HttpServletRequest request) {

        RefreshToken oldToken = refreshTokenRepository.findByToken(oldTokenString)
                .orElseThrow(() -> new InvalidTokenException("Refresh token not found"));

        if (oldToken.isRevoked()) {
            // CRITICAL SECURITY EVENT - Log IMMEDIATELY even if transaction fails
            // We need to know about token reuse attempts regardless of what happens next

            String currentIp = elkAuditService.getClientIp(request);
            String currentFingerprint = generateDeviceFingerprint(request);
            boolean sameDevice = oldToken.getDeviceFingerprint().equals(currentFingerprint);

            String forensicDetails = String.format(
                    "TOKEN REUSE DETECTED | Original IP: %s | Attacker IP: %s | Same Device: %b | Delay: %d min",
                    oldToken.getIpAddress(), currentIp, sameDevice,
                    Duration.between(oldToken.getRevokedAt(), Instant.now()).toMinutes()
            );

            // IMMEDIATE - Security event, log before throwing exception
            elkAuditService.logFailureImmediately(
                    AuditEventType.TOKEN_REUSE_DETECTED,
                    user.getEmail(),
                    forensicDetails
            );

            // Revoke all tokens (this might fail, but we already logged the security event)
            if (getDevicePolicyForUser(user).multiDeviceEnabled()) {
                refreshTokenRepository.deleteByUserAndDeviceFingerprint(user, oldToken.getDeviceFingerprint());
            } else {
                refreshTokenRepository.deleteByUser(user);
            }

            throw new TokenReusedException("Security alert: Token reuse detected. You have been logged out.");
        }

        // Normal rotation - mark old token as revoked
        oldToken.setRevoked(true);
        oldToken.setRevokedAt(Instant.now());

        // Create new token
        RefreshToken newToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .createdAt(Instant.now())
                .revoked(false)
                .ipAddress(elkAuditService.getClientIp(request))
                .userAgent(request.getHeader("User-Agent"))
                .deviceFingerprint(oldToken.getDeviceFingerprint())
                .deviceName(oldToken.getDeviceName())
                .build();

        oldToken.setReplacedByToken(newToken.getToken());

        refreshTokenRepository.save(oldToken);
        RefreshToken saved = refreshTokenRepository.save(newToken);

        // BUFFERED - Only logged if rotation succeeds
        elkAuditService.logSuccess(
                AuditEventType.TOKEN_REFRESHED,
                user,
                String.format("Token rotated for device: %s", oldToken.getDeviceName())
        );

        log.debug("✓ Token rotated: User={}, Device={}",
                user.getEmail(), oldToken.getDeviceName());

        return saved;
    }

    private void removeOldestToken(User user) {
        List<RefreshToken> tokens = refreshTokenRepository.findByUserOrderByCreatedAtAsc(user);
        if (!tokens.isEmpty()) {
            RefreshToken oldest = tokens.getFirst();
            refreshTokenRepository.delete(oldest);

            // BUFFERED - Only logged if removal succeeds
            elkAuditService.logSuccess(
                    AuditEventType.DEVICE_REMOVED,
                    user,
                    "Auto-removed oldest session: " + oldest.getDeviceName()
            );
        }
    }

    @Override
    @Transactional
    public void revokeToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new InvalidTokenException("Refresh token not found"));

        refreshTokenRepository.delete(refreshToken);

        // BUFFERED - Only logged if deletion succeeds
        elkAuditService.logSuccess(
                AuditEventType.TOKEN_REVOKED,
                refreshToken.getUser(),
                "Token revoked for device: " + refreshToken.getDeviceName()
        );
    }

    @Override
    @Transactional
    public void revokeAllUserTokens(User user) {
        int deleted = refreshTokenRepository.deleteByUser(user);

        // BUFFERED - Only logged if deletion succeeds
        elkAuditService.logSuccess(
                AuditEventType.LOGOUT_ALL_DEVICES,
                user,
                "Revoked all " + deleted + " sessions"
        );
    }

    @Override
    @Transactional
    public void revokeAllUserTokens(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        revokeAllUserTokens(user);
    }

    @Override
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.isRevoked()) {
            log.warn("⚠️ Revoked token used: User={}, Device={}",
                    token.getUser().getEmail(),
                    token.getDeviceName());

            // IMMEDIATE - Security event, log before any DB changes
            elkAuditService.logFailureImmediately(
                    AuditEventType.TOKEN_REUSE_DETECTED,
                    token.getUser().getEmail(),
                    "Attempted use of revoked token for device: " + token.getDeviceName()
            );

            DevicePolicy policy = getDevicePolicyForUser(token.getUser());

            // Logic: If they are single-device (Master Admin), they were likely displaced by a new login.
            // If they are multi-device, a revoked token usually means a manual logout or a reuse attack.
            String errorMsg = !policy.multiDeviceEnabled()
                    ? "SESSION_DISPLACED"
                    : "SESSION_REUSED";

            if (policy.multiDeviceEnabled()) {
                refreshTokenRepository.deleteByUserAndDeviceFingerprint(
                        token.getUser(),
                        token.getDeviceFingerprint()
                );
            } else {
                refreshTokenRepository.deleteByUser(token.getUser());
            }

            throw new TokenReusedException(errorMsg);
        }

        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);

            // IMMEDIATE - Log expired token (informational, not critical)
            elkAuditService.logFailureImmediately(
                    AuditEventType.TOKEN_EXPIRED,
                    token.getUser().getEmail(),
                    "Token expired for device: " + token.getDeviceName()
            );

            throw new TokenExpiredException("SESSION_EXPIRED");
        }

        return token;
    }

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Override
    @Transactional
    public int cleanupExpiredTokens() {
        Instant now = Instant.now();
        int deleted = refreshTokenRepository.deleteByExpiryDateBefore(now);
        log.info("Cleaned up {} expired refresh tokens", deleted);
        return deleted;
    }

    @Scheduled(cron = "${app.security.token-cleanup.cron:0 0 3 * * ?}")
    @Transactional
    public void scheduledTokenCleanup() {
        cleanupExpiredTokens();
    }

    @Scheduled(cron = "${app.security.token-cleanup.cron:0 0 3 * * ?}")
    @Transactional
    public void scheduledRevokedTokenCleanup() {
        Instant cutoff = Instant.now().minusSeconds(30 * 24 * 60 * 60);
        int deleted = refreshTokenRepository.deleteRevokedTokensOlderThan(cutoff);
        log.info("Cleaned up {} old revoked tokens", deleted);
    }

    /**
     * Generate enhanced device fingerprint with client-side device ID
     * <p>
     * ENHANCEMENT: Includes X-Device-ID header from client to prevent
     * corporate NAT collisions where multiple users share same IP + User-Agent
     * <p>
     * Format: SHA-256(IP + User-Agent + ClientDeviceID)
     */
    private String generateDeviceFingerprint(HttpServletRequest request) {
        try {
            if (request == null) return "unknown";

            String ip = elkAuditService.getClientIp(request);
            String userAgent = request.getHeader("User-Agent");
            String clientDeviceId = request.getHeader("X-Device-ID");

            String data = String.format("%s|%s|%s",
                    ip != null ? ip : "unknown",
                    userAgent != null ? userAgent : "unknown",
                    clientDeviceId != null ? clientDeviceId : "no-client-id"
            );

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
            return "fallback-" + UUID.randomUUID().toString();
        }
    }

    private String parseDeviceName(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) return "Unknown Device";

        if (userAgent.contains("Windows")) return "Windows PC";
        else if (userAgent.contains("Mac")) return "Mac";
        else if (userAgent.contains("iPhone")) return "iPhone";
        else if (userAgent.contains("iPad")) return "iPad";
        else if (userAgent.contains("Android")) return "Android Device";
        else if (userAgent.contains("Linux")) return "Linux PC";
        else if (userAgent.contains("Postman")) return "Postman";

        return "Unknown Device";
    }

    private String getUserPrimaryRole(User user) {
        if (user.hasRole(AppRole.ROLE_MASTER_ADMIN)) return "MASTER_ADMIN";
        if (user.hasRole(AppRole.ROLE_ADMIN)) return "ADMIN";
        if (user.hasRole(AppRole.ROLE_EMPLOYEE)) return "EMPLOYEE";
        return "CUSTOMER";
    }

    private record DevicePolicy(boolean multiDeviceEnabled, int maxDevices, String roleType) {
    }
}