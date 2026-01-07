package com.rishan.guardianstack.auth.service.impl;

import com.rishan.guardianstack.auth.model.AppRole;
import com.rishan.guardianstack.auth.model.RefreshToken;
import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.auth.repository.RefreshTokenRepository;
import com.rishan.guardianstack.auth.repository.UserRepository;
import com.rishan.guardianstack.auth.service.AuthAuditService;
import com.rishan.guardianstack.auth.service.RefreshTokenService;
import com.rishan.guardianstack.core.exception.InvalidTokenException;
import com.rishan.guardianstack.core.exception.ResourceNotFoundException;
import com.rishan.guardianstack.core.exception.TokenExpiredException;
import com.rishan.guardianstack.core.exception.TokenReusedException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

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
    private final AuthAuditService authAuditService;

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

    /**
     * Creates refresh token with PESSIMISTIC LOCKING to prevent race conditions
     * <p>
     * ENHANCEMENT: Uses SERIALIZABLE isolation level and database-level locking
     * to prevent concurrent login attempts from bypassing device limits
     */
    @Override
    @Transactional(isolation = Isolation.SERIALIZABLE)
    public RefreshToken createRefreshToken(String email, HttpServletRequest request) {

        User user = userRepository.findByEmailForUpdate(email).orElseThrow(() -> new ResourceNotFoundException("User not found"));

        DevicePolicy policy = getDevicePolicyForUser(user);

        log.info("📱 Creating token for user: {} (Role: {}, Policy: {} devices max, Multi-device: {})", email, getUserPrimaryRole(user), policy.maxDevices(), policy.multiDeviceEnabled());

        if (policy.multiDeviceEnabled()) {
            return createRefreshTokenMultiDevice(user, request, policy.maxDevices());
        } else {
            return createRefreshTokenSingleDevice(user, request);
        }
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

    private RefreshToken createRefreshTokenSingleDevice(User user, HttpServletRequest request) {
        int deleted = refreshTokenRepository.deleteByUser(user);
        if (deleted > 0) {
            log.warn("🔒 MASTER_ADMIN single device policy: Deleted {} existing token(s) for user: {}", deleted, user.getEmail());

            authAuditService.logEvent("DEVICE_SESSION_REPLACED", user, true, request != null ? authAuditService.getClientIp(request) : "unknown", request != null ? authAuditService.getUserAgent(request) : "unknown", "Master Admin: Previous device session terminated (single device policy)");
        }
        refreshTokenRepository.flush();

        return buildAndSaveToken(user, request);
    }

    /**
     * IMPROVEMENT #2: Race condition protection with atomic operations
     */
    private RefreshToken createRefreshTokenMultiDevice(User user, HttpServletRequest request, int maxDevices) {
        String deviceFingerprint = generateDeviceFingerprint(request);

        // Check if this device already has a token
        Optional<RefreshToken> existingDeviceToken = refreshTokenRepository.findByUserAndDeviceFingerprint(user, deviceFingerprint);

        if (existingDeviceToken.isPresent()) {
            RefreshToken existing = existingDeviceToken.get();
            log.info("🔄 Same device re-login: {} (user: {})", existing.getDeviceName(), user.getEmail());

            refreshTokenRepository.delete(existing);
            refreshTokenRepository.flush();
        } else {
            // IMPROVEMENT: Use FOR UPDATE to prevent race condition
            // Lock all active tokens for this user during device limit check
            long activeDevices = refreshTokenRepository.countActiveTokensByUserForUpdate(user, Instant.now());

            if (activeDevices >= maxDevices) {
                log.warn("⚠️ Max devices ({}) reached for user: {} (Role: {}). Removing oldest.", maxDevices, user.getEmail(), getUserPrimaryRole(user));

                removeOldestToken(user);

                authAuditService.logEvent("DEVICE_LIMIT_REACHED", user, true, request != null ? authAuditService.getClientIp(request) : "unknown", request != null ? authAuditService.getUserAgent(request) : "unknown", String.format("Device limit (%d) reached, oldest device removed", maxDevices));
            }
        }

        return buildAndSaveToken(user, request);
    }

    private RefreshToken buildAndSaveToken(User user, HttpServletRequest request) {
        String deviceFingerprint = generateDeviceFingerprint(request);
        String deviceName = parseDeviceName(request != null ? request.getHeader("User-Agent") : null);
        String ipAddress = request != null ? authAuditService.getClientIp(request) : "unknown";
        String userAgent = request != null ? request.getHeader("User-Agent") : "unknown";

        RefreshToken refreshToken = RefreshToken.builder().user(user).token(UUID.randomUUID().toString()).expiryDate(Instant.now().plusMillis(refreshTokenDurationMs)).createdAt(Instant.now()).revoked(false).ipAddress(ipAddress).userAgent(userAgent).deviceFingerprint(deviceFingerprint).deviceName(deviceName).build();

        RefreshToken saved = refreshTokenRepository.save(refreshToken);

        // IMPROVEMENT #3: Enhanced audit logging with device details
        authAuditService.logEvent("DEVICE_TOKEN_CREATED", user, true, ipAddress, userAgent, String.format("Session created on %s (Fingerprint: %s, IP: %s)", deviceName, deviceFingerprint.substring(0, 12) + "...", ipAddress));

        log.info("✓ Token created: User={}, Device={}, IP={}, Role={}, Fingerprint={}", user.getEmail(), deviceName, ipAddress, getUserPrimaryRole(user), deviceFingerprint.substring(0, 12) + "...");

        return saved;
    }

    private void removeOldestToken(User user) {
        List<RefreshToken> tokens = refreshTokenRepository.findByUserOrderByCreatedAtAsc(user);
        if (!tokens.isEmpty()) {
            RefreshToken oldest = tokens.getFirst();
            String deviceName = oldest.getDeviceName();
            String ipAddress = oldest.getIpAddress();

            refreshTokenRepository.delete(oldest);

            log.info("🗑️ Removed oldest device token: {} (IP: {}) for user: {}", deviceName, ipAddress, user.getEmail());

            authAuditService.logEvent("DEVICE_TOKEN_AUTO_REMOVED", user, true, ipAddress, oldest.getUserAgent(), String.format("Oldest device (%s) removed due to device limit", deviceName));
        }
    }

    // ==========================================
    // IMPROVEMENT #3: Enhanced Token Reuse Detection with Forensic Logging
    // ==========================================

    /**
     * Rotates refresh token with enhanced forensic logging for insurance compliance
     * <p>
     * ENHANCEMENT: Logs both the original token details AND the attacker's details
     * to help forensic teams identify the source of the compromise
     */
    @Override
    @Transactional
    public RefreshToken rotateRefreshToken(String oldTokenString, User user, HttpServletRequest request) {

        RefreshToken oldToken = refreshTokenRepository.findByToken(oldTokenString).orElseThrow(() -> new InvalidTokenException("Refresh token not found"));

        // CRITICAL: Token Reuse Detection with Forensic Analysis
        if (oldToken.isRevoked()) {
            DevicePolicy policy = getDevicePolicyForUser(user);

            //  Detailed forensic logging
            String originalIp = oldToken.getIpAddress();
            String originalDevice = oldToken.getDeviceName();
            String originalFingerprint = oldToken.getDeviceFingerprint();
            Instant revokedAt = oldToken.getRevokedAt();

            String currentIp = request != null ? authAuditService.getClientIp(request) : "unknown";
            String currentUserAgent = request != null ? authAuditService.getUserAgent(request) : "unknown";
            String currentFingerprint = generateDeviceFingerprint(request);

            // Forensic analysis
            boolean sameDevice = originalFingerprint.equals(currentFingerprint);
            boolean sameIp = originalIp.equals(currentIp);

            log.error("🚨 SECURITY ALERT: TOKEN REUSE DETECTED!");
            log.error("═══════════════════════════════════════════════════════════");
            log.error("User: {}", user.getEmail());
            log.error("Role: {}", getUserPrimaryRole(user));
            log.error("───────────────────────────────────────────────────────────");
            log.error("ORIGINAL TOKEN (Legitimate User):");
            log.error("  - Device: {}", originalDevice);
            log.error("  - IP: {}", originalIp);
            log.error("  - Fingerprint: {}...", originalFingerprint.substring(0, 12));
            log.error("  - Token Revoked At: {}", revokedAt);
            log.error("───────────────────────────────────────────────────────────");
            log.error("REUSE ATTEMPT (Potential Attacker):");
            log.error("  - IP: {}", currentIp);
            log.error("  - User-Agent: {}", currentUserAgent);
            log.error("  - Fingerprint: {}...", currentFingerprint.substring(0, 12));
            log.error("  - Attempt Time: {}", Instant.now());
            log.error("───────────────────────────────────────────────────────────");
            log.error("FORENSIC ANALYSIS:");
            log.error("  - Same Device: {}", sameDevice ? "YES (Replay attack)" : "NO (Token stolen)");
            log.error("  - Same IP: {}", sameIp ? "YES" : "NO");
            log.error("  - Time Since Revocation: {} minutes", Duration.between(revokedAt, Instant.now()).toMinutes());
            log.error("═══════════════════════════════════════════════════════════");

            // Role-based response
            if (policy.multiDeviceEnabled()) {
                int revoked = refreshTokenRepository.deleteByUserAndDeviceFingerprint(user, oldToken.getDeviceFingerprint());
                log.error("Action: Revoked {} token(s) for device: {}", revoked, oldToken.getDeviceName());
            } else {
                int revoked = refreshTokenRepository.deleteByUser(user);
                log.error("Action: MASTER_ADMIN - Revoked ALL {} token(s)", revoked);
            }

            // Forensic audit log
            String forensicDetails = String.format("TOKEN REUSE DETECTED | " + "Original Device: %s (IP: %s) | " + "Reuse Attempt From: IP=%s, UA=%s | " + "Same Device: %s, Same IP: %s | " + "Time Since Revocation: %d min", originalDevice, originalIp, currentIp, currentUserAgent, sameDevice, sameIp, Duration.between(revokedAt, Instant.now()).toMinutes());

            authAuditService.logFailedEvent("TOKEN_REUSE_DETECTED", user.getEmail(), forensicDetails, currentIp, currentUserAgent);

            // Additional alert for Master Admin (highest priority)
            if (user.hasRole(AppRole.ROLE_MASTER_ADMIN)) {
                authAuditService.logEvent("CRITICAL_SECURITY_BREACH_MASTER_ADMIN", user, false, currentIp, currentUserAgent, "CRITICAL: Master Admin token reuse detected - immediate investigation required");
            }

            throw new TokenReusedException("Security alert: This token was already used. " + (policy.multiDeviceEnabled() ? "This device has been logged out. " : "All devices have been logged out. ") + "Please login again. If this wasn't you, change your password immediately.");
        }


        // Normal rotation
        oldToken.setRevoked(true);
        oldToken.setRevokedAt(Instant.now());

        RefreshToken newToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .createdAt(Instant.now())
                .revoked(false)
                .ipAddress(oldToken.getIpAddress())
                .userAgent(oldToken.getUserAgent())
                .deviceFingerprint(oldToken.getDeviceFingerprint())
                .deviceName(oldToken.getDeviceName())
                .build();

        oldToken.setReplacedByToken(newToken.getToken());

        refreshTokenRepository.save(oldToken);
        RefreshToken saved = refreshTokenRepository.save(newToken);

        log.debug("✓ Token rotated: User={}, Device={}",
                user.getEmail(), oldToken.getDeviceName());

        return saved;
    }

    @Override
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.isRevoked()) {
            log.warn("⚠️ Revoked token used: User={}, Device={}",
                    token.getUser().getEmail(),
                    token.getDeviceName());

            DevicePolicy policy = getDevicePolicyForUser(token.getUser());

            if (policy.multiDeviceEnabled()) {
                refreshTokenRepository.deleteByUserAndDeviceFingerprint(
                        token.getUser(),
                        token.getDeviceFingerprint()
                );
            } else {
                refreshTokenRepository.deleteByUser(token.getUser());
            }

            throw new TokenReusedException("This token was already used.");
        }

        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenExpiredException("Token has expired. Please sign in again.");
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

        authAuditService.logEvent(
                "DEVICE_LOGOUT",
                refreshToken.getUser(),
                true,
                refreshToken.getIpAddress(),
                refreshToken.getUserAgent(),
                String.format("User logged out from %s", refreshToken.getDeviceName())
        );
    }

    @Override
    @Transactional
    public void revokeAllUserTokens(User user) {
        int deleted = refreshTokenRepository.deleteByUser(user);

        authAuditService.logEvent(
                "ALL_DEVICES_LOGOUT",
                user,
                true,
                "system",
                "system",
                String.format("All %d device(s) logged out", deleted)
        );

        log.info("Revoked {} token(s) for user: {}", deleted, user.getEmail());
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

            String ip = authAuditService.getClientIp(request);
            String userAgent = request.getHeader("User-Agent");

            // ENHANCEMENT: Include client-side device ID if present
            String clientDeviceId = request.getHeader("X-Device-ID");

            // Build fingerprint data
            String data = String.format("%s|%s|%s", ip != null ? ip : "unknown", userAgent != null ? userAgent : "unknown", clientDeviceId != null ? clientDeviceId : "no-client-id");

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            String fingerprint = hexString.toString();

            log.debug("Generated device fingerprint: {} (IP: {}, UA: {}, ClientID: {})", fingerprint.substring(0, 12) + "...", ip, userAgent != null ? userAgent.substring(0, Math.min(50, userAgent.length())) : "none", clientDeviceId != null ? "present" : "absent");

            return fingerprint;

        } catch (Exception e) {
            log.error("Failed to generate device fingerprint, using fallback", e);
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