package com.rishan.guardianstack.auth.repository;

import com.rishan.guardianstack.auth.model.User;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
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

    List<User> findUsersWithExpiringAccounts(int warningDays);
    List<User> findUsersWithExpiringCredentials(int warningDays);
    List<User> findExpiredAccounts();

    /**
     * Find all users with expired credentials (passwords)
     */
    @Query("SELECT u FROM User u WHERE u.credentialsExpiryDate < CURRENT_TIMESTAMP")
    List<User> findUsersWithExpiredCredentials();

}