package com.rishan.guardianstack.auth.repository;

import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.auth.model.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {

    Optional<VerificationToken> findByUserAndTokenTypeAndVerifiedFalse(User user, String tokenType);

    Optional<VerificationToken> findFirstByUserAndTokenTypeOrderByCreatedAtDesc(User user, String tokenType);

    void deleteByUserAndTokenType(User user, String tokenType);

    int deleteByExpiryDateBefore(LocalDateTime expiryDate);

    void deleteByUser(User user);
}