package com.rishan.guardianstack.masteradmin.user.dto;

import com.rishan.guardianstack.auth.model.Role;

import java.time.LocalDateTime;
import java.util.Set;

public record UpdateUserRequestDTO(
        String username,
        String email,
        String password,
        Set<Integer> roleIds,
        boolean enabled,
        boolean mustChangePassword,
        Integer passwordValidityDays,
        LocalDateTime lockedUntil,
        LocalDateTime accountExpiryDate,
        LocalDateTime credentialsExpiryDate
) {
}
