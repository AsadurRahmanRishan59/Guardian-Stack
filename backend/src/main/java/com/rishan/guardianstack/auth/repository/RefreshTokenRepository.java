package com.rishan.guardianstack.auth.repository;

import com.rishan.guardianstack.auth.model.RefreshToken;
import com.rishan.guardianstack.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    @Modifying
    @Query("DELETE FROM RefreshToken r WHERE r.user = :user")
    int deleteByUser(User user);

    @Modifying
    @Query("DELETE FROM RefreshToken r WHERE r.expiryDate < :cutoff")
    int deleteByExpiryDateBefore(Instant cutoff);

    @Modifying
    @Query("DELETE FROM RefreshToken r WHERE r.revoked = true AND r.createdAt < :cutoff")
    int deleteRevokedTokensOlderThan(Instant cutoff);
}