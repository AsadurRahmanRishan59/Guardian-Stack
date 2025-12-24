package com.rishan.guardianstack.auth.repository;

import com.rishan.digitalinsurance.modules.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {
    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    //check email excluding specific user
    Optional<User> findByEmailAndUserIdNot(String email, Long id);

    // This allows you to find the user regardless of which identifier they provide
    Optional<User> findByEmailOrMobileNumber(String email, String mobileNumber);

    boolean existsByEmail(String email);

    boolean existsByMobileNumber(String mobileNumber);
}
