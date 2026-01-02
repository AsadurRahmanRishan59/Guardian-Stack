package com.rishan.guardianstack.masteradmin.user.dto;

import com.rishan.guardianstack.auth.model.Role;
import com.rishan.guardianstack.auth.model.SignUpMethod;

import java.time.LocalDateTime;
import java.util.Set;

public record MasterAdminUserViewDTO(
        Long userId,
        String username,
        String email,
        boolean accountNonLocked,
        boolean accountNonExpired,
        boolean enabled,
        SignUpMethod signUpMethod,
        Set<Role> roles,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {
}
