package com.rishan.guardianstack.masteradmin.user.dto;

import com.rishan.guardianstack.auth.model.SignUpMethod;
import java.time.LocalDateTime;
import java.util.Set;

public record MasterAdminUserViewDTO(
        Long userId,
        String username,
        String email,
        Boolean enabled,
        Boolean accountLocked,
        Boolean accountExpired,
        Boolean credentialExpired,
        SignUpMethod signUpMethod,
        Set<String> roles,
        LocalDateTime createdAt,
        String createdBy
) {
}
