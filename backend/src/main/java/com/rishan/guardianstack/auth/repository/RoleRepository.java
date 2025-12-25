package com.rishan.guardianstack.auth.repository;

import com.rishan.guardianstack.auth.model.AppRole;
import com.rishan.guardianstack.auth.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByRoleName(AppRole roleName);
}
