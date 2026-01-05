package com.rishan.guardianstack.auth.repository;

import com.rishan.guardianstack.auth.model.RefreshToken;
import com.rishan.guardianstack.auth.model.User;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findByUser(User user);

    List<RefreshToken> findByUserOrderByCreatedAtAsc(User user);

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user = :user AND rt.deviceFingerprint = :fingerprint AND rt.revoked = false")
    Optional<RefreshToken> findByUserAndDeviceFingerprint(
            @Param("user") User user,
            @Param("fingerprint") String deviceFingerprint
    );

    /**
     * IMPROVEMENT #2: Count with pessimistic lock to prevent race conditions
     * Locks the rows being counted to prevent concurrent inserts
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.user = :user AND rt.revoked = false AND rt.expiryDate > :now")
    long countActiveTokensByUserForUpdate(@Param("user") User user, @Param("now") Instant now);

    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.user = :user AND rt.revoked = false AND rt.expiryDate > :now")
    long countActiveTokensByUser(@Param("user") User user, @Param("now") Instant now);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.user = :user")
    int deleteByUser(@Param("user") User user);

    /**
     * Find all active (non-revoked) tokens for a user
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user = :user AND rt.revoked = false")
    List<RefreshToken> findActiveTokensByUser(@Param("user") User user);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.user = :user AND rt.deviceFingerprint = :fingerprint")
    int deleteByUserAndDeviceFingerprint(
            @Param("user") User user,
            @Param("fingerprint") String deviceFingerprint
    );

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :cutoff")
    int deleteByExpiryDateBefore(@Param("cutoff") Instant cutoff);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.revoked = true AND rt.revokedAt < :cutoff")
    int deleteRevokedTokensOlderThan(@Param("cutoff") Instant cutoff);

    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user = :user AND rt.revoked = false AND rt.expiryDate > :now ORDER BY rt.createdAt DESC")
    List<RefreshToken> findActiveDevicesByUser(@Param("user") User user, @Param("now") Instant now);
}