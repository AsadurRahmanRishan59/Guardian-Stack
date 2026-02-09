package com.rishan.guardianstack.auth.repository;

import com.rishan.guardianstack.auth.model.User;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {

    Optional<User> findByEmail(String email);

    /**
     * IMPROVEMENT #2: Pessimistic locking to prevent race conditions
     * SELECT FOR UPDATE prevents concurrent token creation for same user
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT u FROM User u WHERE u.email = :email")
    Optional<User> findByEmailForUpdate(@Param("email") String email);

    boolean existsByEmail(String email);

    // Useful for profile updates (ignore current user)
    Optional<User> findByEmailAndUserIdNot(String email, Long id);

    @Query("SELECT u FROM User u WHERE u.accountExpiryDate IS NOT NULL AND u.accountExpiryDate <= :threshold")
    List<User> findUsersWithExpiringAccounts(@Param("threshold") LocalDateTime threshold);

    @Query("SELECT u FROM User u WHERE u.credentialsExpiryDate IS NOT NULL AND u.credentialsExpiryDate <= :threshold")
    List<User> findUsersWithExpiringCredentials(@Param("threshold") LocalDateTime threshold);

    @Query("SELECT u FROM User u WHERE u.accountExpiryDate IS NOT NULL AND u.accountExpiryDate < CURRENT_TIMESTAMP")
    List<User> findExpiredAccounts();

    @Query("SELECT u FROM User u WHERE u.credentialsExpiryDate IS NOT NULL AND u.credentialsExpiryDate < CURRENT_TIMESTAMP")
    List<User> findUsersWithExpiredCredentials();


    /**
     * Increment failed login attempts without triggering audit.
     * Called on each failed login attempt.
     */
    @Modifying
    @Query(value = """
        UPDATE gs_users 
        SET failed_login_attempts = failed_login_attempts + 1,
            last_failed_login = :timestamp
        WHERE user_id = :userId
        """, nativeQuery = true)
    void incrementFailedAttemptsWithoutAudit(
            @Param("userId") Long userId,
            @Param("timestamp") LocalDateTime timestamp
    );

    /**
     * Lock account without triggering audit.
     * Called when max failed attempts is reached.
     */
    @Modifying
    @Query(value = """
        UPDATE gs_users 
        SET account_locked = true,
            locked_until = :lockedUntil
        WHERE user_id = :userId
        """, nativeQuery = true)
    void lockAccountWithoutAudit(
            @Param("userId") Long userId,
            @Param("lockedUntil") LocalDateTime lockedUntil
    );

    /**
     * Reset failed login attempts without triggering audit.
     * Called on successful login, password reset, and manual unlock.
     */
    @Modifying
    @Query(value = """
        UPDATE gs_users 
        SET failed_login_attempts = 0,
            last_failed_login = NULL,
            account_locked = false,
            locked_until = NULL,
            last_successful_login = :timestamp
        WHERE user_id = :userId
        """, nativeQuery = true)
    void resetFailedAttemptsWithoutAudit(
            @Param("userId") Long userId,
            @Param("timestamp") LocalDateTime timestamp
    );

    /**
     * Update only last successful login timestamp.
     * Used when you want to track login time without resetting failed attempts.
     */
    @Modifying
    @Query(value = """
        UPDATE gs_users 
        SET last_successful_login = :timestamp
        WHERE user_id = :userId
        """, nativeQuery = true)
    void updateLastSuccessfulLoginWithoutAudit(
            @Param("userId") Long userId,
            @Param("timestamp") LocalDateTime timestamp
    );
}


