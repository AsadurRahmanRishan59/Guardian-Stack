package com.rishan.guardianstack.auth.service.impl;

import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.auth.model.VerificationToken;
import com.rishan.guardianstack.auth.repository.UserRepository;
import com.rishan.guardianstack.auth.repository.VerificationTokenRepository;
import com.rishan.guardianstack.auth.service.VerificationService;
import com.rishan.guardianstack.core.exception.VerificationException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class VerificationServiceImpl implements VerificationService {

    private final VerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;

    @Override
    @Transactional
    public String createToken(User user) {
        // 1. Check Cooldown (60 seconds)
        tokenRepository.findFirstByUserOrderByTokenIdDesc(user)
                .ifPresent(lastToken -> {
                    // Since you use BaseEntity, we have getCreatedAt()
                    if (lastToken.getCreatedAt().isAfter(LocalDateTime.now().minusSeconds(60))) {
                        throw new VerificationException("Please wait 60 seconds before requesting a new code.");
                    }
                });

        // 2. Clean up old tokens to keep the DB small
        tokenRepository.deleteByUser(user);

        // 3. Generate and Save new token
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
    public User verifyToken(String email, String otp) {
        VerificationToken verificationToken = tokenRepository.findByUserEmailAndToken(email, otp)
                .orElseThrow(() -> new RuntimeException("Invalid Token or Email"));

        if (verificationToken.isExpired()) {
            throw new RuntimeException("Token has expired");
        }

        if (verificationToken.getConfirmedAt() != null) {
            throw new RuntimeException("Email already verified");
        }

        // Success: Activate the user
        User user = verificationToken.getUser();
        user.setEnabled(true);
        userRepository.save(user);

        verificationToken.setConfirmedAt(LocalDateTime.now());
        tokenRepository.save(verificationToken);

        return user;
    }

    @Override
    @Transactional
    public String createPasswordResetToken(User user) {
        // 1. Delete any old reset tokens for this user
        tokenRepository.deleteByUserAndTokenType(user, "PASSWORD_RESET");

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