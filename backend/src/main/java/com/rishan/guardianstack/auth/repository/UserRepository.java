package com.rishan.guardianstack.auth.repository;

import com.rishan.guardianstack.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {

    // Primary login lookup
    Optional<User> findByEmail(String email);

    // For checking uniqueness during signup
    boolean existsByEmail(String email);

    // Useful for profile updates (ignore current user)
    Optional<User> findByEmailAndUserIdNot(String email, Long id);
}