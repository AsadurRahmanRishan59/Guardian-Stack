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
                .orElseThrow(() -> handleFailure(email, AuditEventType.EMAIL_VERIFICATION_FAILED, "No pending verification found"));

        // 1. Centralized Check
        performOtpCheck(token, otp, email, AuditEventType.EMAIL_VERIFICATION_FAILED);

        // 2. Finalize (Enable user)
        token.setVerified(true);
        token.setVerifiedAt(LocalDateTime.now());
        user.setEnabled(true);

        tokenRepository.save(token);
        userRepository.save(user);

        elkAuditService.logSuccess(AuditEventType.EMAIL_VERIFIED, user, "Email verified successfully");
        return user;
    }

    @Override
    @Transactional
    public User verifyPasswordResetToken(String email, String otp) {
        User user = getUserByEmail(email, AuditEventType.PASSWORD_RESET_FAILED);

        VerificationToken token = tokenRepository
                .findByUserAndTokenTypeAndVerifiedFalse(user, TokenType.PASSWORD_RESET.name())
                .orElseThrow(() -> handleFailure(email, AuditEventType.PASSWORD_RESET_FAILED, "Invalid or missing reset code"));

        // 1. Centralized Check
        performOtpCheck(token, otp, email, AuditEventType.PASSWORD_RESET_FAILED);

        // 2. Consume Token (Prevents Replay)
        token.setVerified(true);
        token.setVerifiedAt(LocalDateTime.now());
        tokenRepository.save(token);

        elkAuditService.logSuccess(AuditEventType.PASSWORD_RESET_INITIATED, user, "Reset OTP verified");
        return user;
    }

    // ==========================================
    // CORE LOGIC (THE "CONSISTENCY" FIX)
    // ==========================================

    private void performOtpCheck(VerificationToken token, String providedOtp, String email, AuditEventType event) {
        // Step 1: Check Expiry and Increment Attempts
        // We use saveAndFlush to ensure the attempt is recorded even if the OTP check fails
        validateTokenState(token, email, event);

        // Step 2: Secret Comparison
        if (!token.getToken().equals(providedOtp)) {
            int remaining = maxVerificationAttempts - token.getVerificationAttempts();
            elkAuditService.logFailure(event, email, "Incorrect OTP entry");

            if (remaining <= 0) {
                tokenRepository.delete(token); // Scrub the token if attempts exhausted
                throw new InvalidTokenException("Maximum attempts exceeded. This code is now invalid.");
            }
            throw new InvalidTokenException("Invalid verification code. " + remaining + " attempts remaining.");
        }
    }

    private void validateTokenState(VerificationToken token, String email, AuditEventType event) {
        // 1. Check Expiry
        if (token.getExpiryDate().isBefore(LocalDateTime.now())) {
            tokenRepository.delete(token);
            throw handleFailure(email, event, "Verification code has expired.");
        }

        // 2. Check Attempts BEFORE incrementing
        if (token.getVerificationAttempts() >= maxVerificationAttempts) {
            tokenRepository.delete(token);
            throw handleFailure(email, event, "Maximum verification attempts exceeded.");
        }

        // 3. Increment and push to DB
        token.incrementAttempts();
        tokenRepository.saveAndFlush(token);
    }

    // ==========================================
    // HELPERS & HOUSEKEEPING
    // ==========================================

    private String createTokenInternal(User user, TokenType type, AuditEventType auditEvent) {
        checkCooldown(user, type);
        tokenRepository.deleteByUserAndTokenType(user, type.name());
        tokenRepository.flush();

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
        elkAuditService.logSuccess(auditEvent, user, type + " OTP generated");
        return otp;
    }

    private void checkCooldown(User user, TokenType type) {
        tokenRepository.findFirstByUserAndTokenTypeOrderByCreatedAtDesc(user, type.name())
                .ifPresent(lastToken -> {
                    long elapsed = Duration.between(lastToken.getCreatedAt(), LocalDateTime.now()).getSeconds();
                    if (elapsed < cooldownSeconds) {
                        long wait = cooldownSeconds - elapsed;
                        throw new VerificationException("Please wait " + wait + " seconds before requesting a new code.");
                    }
                });
    }

    @Scheduled(cron = "0 0 * * * *") // Every hour
    @Transactional
    public void cleanupExpiredTokens() {
        tokenRepository.deleteByExpiryDateBefore(LocalDateTime.now());
    }

    private User getUserByEmail(String email, AuditEventType event) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    elkAuditService.logFailure(event, email, "User not found");
                    return new ResourceNotFoundException("User not found", "email");
                });
    }

    private InvalidTokenException handleFailure(String email, AuditEventType event, String reason) {
        elkAuditService.logFailure(event, email, reason);
        return new InvalidTokenException(reason);
    }

    private String generateOTP() {
        return RANDOM.ints(otpLength, 0, OTP_CHARACTERS.length())
                .mapToObj(OTP_CHARACTERS::charAt)
                .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
                .toString();
    }
}