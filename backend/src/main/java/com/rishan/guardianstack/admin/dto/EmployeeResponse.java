package com.rishan.guardianstack.admin.dto;

// ==========================================
// EMPLOYEE RESPONSE
// ==========================================

import com.rishan.guardianstack.auth.model.AppRole;
import com.rishan.guardianstack.auth.model.Role;
import com.rishan.guardianstack.auth.model.User;

import java.time.LocalDateTime;

public record EmployeeResponse(
        Long userId,
        String username,
        String email,
        AppRole role,
        boolean enabled,
        LocalDateTime accountExpiryDate,
        LocalDateTime credentialsExpiryDate,
        boolean mustChangePassword,
        Long daysUntilExpiry,
        Long daysUntilPasswordExpiry,
        LocalDateTime lastSuccessfulLogin,
        LocalDateTime createdAt,
        String createdBy
) {
    public static EmployeeResponse from(User user) {
        AppRole primaryRole = user.getRoles().stream()
                .map(Role::getRoleName)
                .filter(r -> r != AppRole.ROLE_USER)
                .findFirst()
                .orElse(AppRole.ROLE_EMPLOYEE);

        return new EmployeeResponse(
                user.getUserId(),
                user.getUsername(),
                user.getEmail(),
                primaryRole,
                user.isEnabled(),
                user.getAccountExpiryDate(),
                user.getCredentialsExpiryDate(),
                user.isMustChangePassword(),
                user.getDaysUntilAccountExpiry(),
                user.getDaysUntilPasswordExpiry(),
                user.getLastSuccessfulLogin(),
                user.getCreatedAt(),
                user.getCreatedBy()
        );
    }
}
