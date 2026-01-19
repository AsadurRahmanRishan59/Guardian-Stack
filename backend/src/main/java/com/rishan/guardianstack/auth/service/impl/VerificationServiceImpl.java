package com.rishan.guardianstack.auth.service.impl;

import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.auth.model.VerificationToken;
import com.rishan.guardianstack.auth.model.TokenType;
import com.rishan.guardianstack.auth.repository.UserRepository;
import com.rishan.guardianstack.auth.repository.VerificationTokenRepository;
import com.rishan.guardianstack.auth.service.ELKAuditService;
import com.rishan.guardianstack.auth.service.VerificationService;
import com.rishan.guardianstack.core.exception.InvalidTokenException;
import com.rishan.guardianstack.core.exception.ResourceNotFoundException;
import com.rishan.guardianstack.core.exception.VerificationException;
import com.rishan.guardianstack.core.logging.AuditEventType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class VerificationServiceImpl implements VerificationService {

    private final VerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final ELKAuditService elkAuditService;

    @Value("${app.security.verification.otp-length:6}")
    private int otpLength;

    @Value("${app.security.verification.expiry-minutes:15}")
    private int expiryMinutes;

    @Value("${app.security.verification.max-attempts:3}")
    private int maxVerificationAttempts;

    @Value("${app.security.verification.cooldown-seconds:60}")
    private int cooldownSeconds;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String OTP_CHARACTERS = "0123456789";

    // ==========================================
    // PUBLIC API
    // ==========================================

    @Override
    @Transactional
    public String createEmailVerificationToken(User user) {
        return createTokenInternal(user, TokenType.EMAIL_VERIFICATION, AuditEventType.OTP_SENT);
    }

    @Override
    @Transactional
    public String createPasswordResetToken(User user) {
        return createTokenInternal(user, TokenType.PASSWORD_RESET, AuditEventType.OTP_SENT);
    }

    @Override
    @Transactional
    public User verifyEmailVerificationToken(String email, String otp) {
        User user = getUserByEmail(email, AuditEventType.EMAIL_VERIFICATION_FAILED);

        VerificationToken token = tokenRepository
                .findByUserAndTokenTypeAndVerifiedFalse(user, TokenType.EMAIL_VERIFICATION.name())
                .orElseThrow(() -> handleFailure(
                        email,
                        AuditEventType.EMAIL_VERIFICATION_FAILED,
                        "No pending verification found"
                ));

        // Perform OTP check (will log failures immediately)
        performOtpCheck(token, otp, email, AuditEventType.EMAIL_VERIFICATION_FAILED);

        // Finalize verification
        token.setVerified(true);
        token.setVerifiedAt(LocalDateTime.now());
        user.setEnabled(true);

        tokenRepository.save(token);
        userRepository.save(user);

        // BUFFERED - Only logged if user activation succeeds
        elkAuditService.logSuccess(
                AuditEventType.EMAIL_VERIFIED,
                user,
                "Email verified successfully"
        );

        return user;
    }

    @Override
    @Transactional
    public User verifyPasswordResetToken(String email, String otp) {
        User user = getUserByEmail(email, AuditEventType.PASSWORD_RESET_FAILED);

        VerificationToken token = tokenRepository
                .findByUserAndTokenTypeAndVerifiedFalse(user, TokenType.PASSWORD_RESET.name())
                .orElseThrow(() -> handleFailure(
                        email,
                        AuditEventType.PASSWORD_RESET_FAILED,
                        "Invalid or missing reset code"
                ));

        // Perform OTP check (will log failures immediately)
        performOtpCheck(token, otp, email, AuditEventType.PASSWORD_RESET_FAILED);

        // Consume token (prevents replay)
        token.setVerified(true);
        token.setVerifiedAt(LocalDateTime.now());
        tokenRepository.save(token);

        // BUFFERED - Only logged if token verification succeeds
        elkAuditService.logSuccess(
                AuditEventType.PASSWORD_RESET_INITIATED,
                user,
                "Reset OTP verified"
        );

        return user;
    }

    // ==========================================
    // CORE VALIDATION LOGIC
    // ==========================================

    /**
     * Centralized OTP validation with immediate failure logging
     *
     * CRITICAL: Failures are logged IMMEDIATELY because:
     * 1. Invalid OTP attempts are security events (even if transaction rolls back)
     * 2. We increment attempt counter BEFORE checking OTP (need to track brute force)
     * 3. If transaction fails, we still want to know about the failed attempt
     */
    private void performOtpCheck(VerificationToken token, String providedOtp,
                                 String email, AuditEventType event) {
        // Step 1: Validate token state and increment attempts
        // saveAndFlush ensures attempt is recorded even if OTP check fails
        validateTokenState(token, email, event);

        // Step 2: Compare OTP
        if (!token.getToken().equals(providedOtp)) {
            int remaining = maxVerificationAttempts - token.getVerificationAttempts();

            // IMMEDIATE - Security event (failed OTP attempt)
            // Must log even if transaction rolls back
            elkAuditService.logFailureImmediately(
                    event,
                    email,
                    String.format("Incorrect OTP entry (attempt %d/%d)",
                            token.getVerificationAttempts(), maxVerificationAttempts)
            );

            if (remaining <= 0) {
                tokenRepository.delete(token);
                throw new InvalidTokenException(
                        "Maximum attempts exceeded. This code is now invalid."
                );
            }

            throw new InvalidTokenException(
                    "Invalid verification code. " + remaining + " attempts remaining."
            );
        }
    }

    /**
     * Validate token state and increment attempt counter
     * Uses saveAndFlush to ensure attempt tracking survives rollbacks
     */
    private void validateTokenState(VerificationToken token, String email, AuditEventType event) {
        // Check expiry
        if (token.getExpiryDate().isBefore(LocalDateTime.now())) {
            tokenRepository.delete(token);

            // IMMEDIATE - Log expired token usage
            elkAuditService.logFailureImmediately(
                    event,
                    email,
                    "Verification code has expired"
            );

            throw new InvalidTokenException("Verification code has expired.");
        }

        // Check attempts BEFORE incrementing
        if (token.getVerificationAttempts() >= maxVerificationAttempts) {
            tokenRepository.delete(token);

            // IMMEDIATE - Log max attempts exceeded
            elkAuditService.logFailureImmediately(
                    event,
                    email,
                    "Maximum verification attempts exceeded"
            );

            throw new InvalidTokenException("Maximum verification attempts exceeded.");
        }

        // Increment and persist immediately
        // This ensures the attempt is counted even if the OTP is wrong
        // and the transaction rolls back
        token.incrementAttempts();
        tokenRepository.saveAndFlush(token);
    }

    // ==========================================
    // TOKEN CREATION & MANAGEMENT
    // ==========================================

    /**
     * Creates a new verification token
     * BUFFERED logging - only logged if token creation succeeds
     */
    private String createTokenInternal(User user, TokenType type, AuditEventType auditEvent) {
        // Check cooldown
        checkCooldown(user, type);

        // Clean up old tokens
        tokenRepository.deleteByUserAndTokenType(user, type.name());
        tokenRepository.flush();

        // Generate and save new token
        String otp = generateOTP();
        VerificationToken token = VerificationToken.builder()
                .token(otp)
                .user(user)
                .expiryDate(LocalDateTime.now().plusMinutes(expiryMinutes))
                .tokenType(type.name())
                .verified(false)
                .verificationAttempts(0)
                .build();

        tokenRepository.save(token);

        // BUFFERED - Only logged if token save succeeds
        elkAuditService.logSuccess(
                auditEvent,
                user,
                type + " OTP generated (expires in " + expiryMinutes + " minutes)"
        );

        return otp;
    }

    /**
     * Enforces cooldown period between OTP requests
     * IMMEDIATE logging for cooldown violations
     */
    private void checkCooldown(User user, TokenType type) {
        tokenRepository.findFirstByUserAndTokenTypeOrderByCreatedAtDesc(user, type.name())
                .ifPresent(lastToken -> {
                    long elapsed = Duration.between(
                            lastToken.getCreatedAt(),
                            LocalDateTime.now()
                    ).getSeconds();

                    if (elapsed < cooldownSeconds) {
                        long wait = cooldownSeconds - elapsed;

                        // IMMEDIATE - Rate limiting event
                        elkAuditService.logFailureImmediately(
                                AuditEventType.RATE_LIMIT_EXCEEDED,
                                user.getEmail(),
                                String.format("OTP cooldown: %d seconds remaining", wait)
                        );

                        throw new VerificationException(
                                "Please wait " + wait + " seconds before requesting a new code."
                        );
                    }
                });
    }

    // ==========================================
    // CLEANUP & UTILITIES
    // ==========================================

    @Scheduled(cron = "0 0 * * * *") // Every hour
    @Transactional
    public void cleanupExpiredTokens() {
        int deleted = tokenRepository.deleteByExpiryDateBefore(LocalDateTime.now());
        if (deleted > 0) {
            log.info("🧹 Cleaned up {} expired verification tokens", deleted);
        }
    }

    /**
     * Get user by email with immediate failure logging
     */
    private User getUserByEmail(String email, AuditEventType event) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    // IMMEDIATE - User not found
                    elkAuditService.logFailureImmediately(
                            event,
                            email,
                            "User not found"
                    );
                    return new ResourceNotFoundException("User not found", "email");
                });
    }

    /**
     * Helper to log failure and create exception
     * Always uses IMMEDIATE logging
     */
    private InvalidTokenException handleFailure(String email, AuditEventType event, String reason) {
        // IMMEDIATE - Verification failure
        elkAuditService.logFailureImmediately(event, email, reason);
        return new InvalidTokenException(reason);
    }

    /**
     * Generate cryptographically secure OTP
     */
    private String generateOTP() {
        return RANDOM.ints(otpLength, 0, OTP_CHARACTERS.length())
                .mapToObj(OTP_CHARACTERS::charAt)
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
                .toString();
    }
}