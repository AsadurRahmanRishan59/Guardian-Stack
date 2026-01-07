package com.rishan.guardianstack.auth.service.impl;

import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.auth.model.VerificationToken;
import com.rishan.guardianstack.auth.repository.UserRepository;
import com.rishan.guardianstack.auth.repository.VerificationTokenRepository;
import com.rishan.guardianstack.auth.service.AuthAuditService;
import com.rishan.guardianstack.auth.service.VerificationService;
import com.rishan.guardianstack.core.exception.InvalidTokenException;
import com.rishan.guardianstack.core.exception.TokenExpiredException;
import com.rishan.guardianstack.core.exception.VerificationException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class VerificationServiceImpl implements VerificationService {

    private final VerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final AuthAuditService authAuditService;

    @Override
    @Transactional
    public String createToken(User user) {
        Optional<VerificationToken> lastToken =
                tokenRepository.findFirstByUserOrderByCreatedAtDesc(user);

        if (lastToken.isPresent() &&
                lastToken.get().getCreatedAt().isAfter(LocalDateTime.now().minusSeconds(60))) {
            throw new VerificationException(
                    "Please wait 60 seconds before requesting a new code."
            );
        }


        tokenRepository.deleteByUser(user);


        SecureRandom secureRandom = new SecureRandom();
        String otp = String.format("%06d", secureRandom.nextInt(1000000));

        VerificationToken verificationToken = VerificationToken.builder()
                .token(otp)
                .tokenType("EMAIL_VERIFICATION")
                .user(user)
                .expiryDate(LocalDateTime.now().plusMinutes(15))
                .build();

        tokenRepository.save(verificationToken);
        return otp;
    }

    @Override
    @Transactional
    public User verifyToken(String email, String otp, HttpServletRequest request) {
        try {
            // 1. Find and Validate Token
            VerificationToken verificationToken = tokenRepository.findByUserEmailAndToken(email, otp)
                    .orElseThrow(() -> new InvalidTokenException("Invalid verification code"));

            // 2. State Checks
            if (verificationToken.isExpired()) {
                throw new TokenExpiredException("Token has expired");
            }
            if (verificationToken.getConfirmedAt() != null) {
                throw new VerificationException("Email already verified");
            }

            User user = verificationToken.getUser();

            // 3. ATOMIC UPDATE (The Practical Part)
            // We link these two actions so they fail or succeed together
            if ("EMAIL_VERIFICATION".equals(verificationToken.getTokenType())) {
                user.setEnabled(true);
                userRepository.save(user); // If this fails, the token update below rolls back
            }

            verificationToken.setConfirmedAt(LocalDateTime.now());
            tokenRepository.save(verificationToken);

            // Success is returned to AuthService, which handles the Success Audit
            return user;

        } catch (Exception e) {
            // 4. Forensic Logging for Failures
            authAuditService.logFailedEvent(
                    "OTP_VERIFICATION_FAILED",
                    email,
                    e.getMessage(),
                    authAuditService.getClientIp(request),
                    authAuditService.getUserAgent(request)
            );
            throw e;
        }
    }
    @Override
    @Transactional
    public String createPasswordResetToken(User user) {
        // 1. Delete any old reset tokens for this user
        tokenRepository.deleteByUserAndTokenType(user, "PASSWORD_RESET");

        tokenRepository.flush();

        // 2. Generate 6-digit OTP
        String otp = String.format("%06d", new SecureRandom().nextInt(1000000));

        // 3. Save a new token
        VerificationToken resetToken = VerificationToken.builder()
                .token(otp)
                .user(user)
                .tokenType("PASSWORD_RESET")
                .expiryDate(LocalDateTime.now().plusMinutes(10)) // Shorter expiry for security
                .build();

        tokenRepository.save(resetToken);
        return otp;
    }
}