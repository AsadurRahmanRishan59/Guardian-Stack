package com.rishan.guardianstack.auth.repository;

import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.auth.model.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {

    Optional<VerificationToken> findByUserEmailAndToken(String email, String otp);

    // Find the latest token for a user to check cooldown
    Optional<VerificationToken> findFirstByUserOrderByCreatedAtDesc(User user);

    // Clean up old tokens for a user
    void deleteByUser(User user);

    void deleteByUserAndTokenType(User user, String passwordReset);

    Optional<VerificationToken> findByTokenAndTokenType(String token, String tokenType);

    List<VerificationToken> findByUser(User user);
}
