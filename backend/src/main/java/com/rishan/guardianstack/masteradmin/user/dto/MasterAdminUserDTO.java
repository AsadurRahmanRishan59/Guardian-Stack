package com.rishan.guardianstack.masteradmin.user.dto;

import com.rishan.guardianstack.auth.model.Role;
import com.rishan.guardianstack.auth.model.SignUpMethod;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Set;

public record MasterAdminUserDTO(
        Long userId,
        String username,
        String email,
        boolean accountNonLocked,
        boolean accountNonExpired,
        boolean credentialsNonExpired,
        boolean enabled,
        LocalDate credentialsExpiryDate,
        LocalDate accountExpiryDate,
        SignUpMethod signUpMethod,
        Set<Role> roles,
        LocalDateTime createdAt,
        LocalDateTime updatedAt,
        String createdBy,
        String updatedBy
) {
}
