package com.rishan.guardianstack.masteradmin.user.dto;

import com.rishan.guardianstack.auth.model.Role;
import com.rishan.guardianstack.auth.model.SignUpMethod;

import java.time.LocalDateTime;
import java.util.Set;

public record MasterAdminUserDTO(
        // --- CORE IDENTITY ---
        Long userId,
        String username,
        String email,
        Set<Role> roles,
        SignUpMethod signUpMethod,

        // --- ACCOUNT STATUS & PERMISSIONS ---
        Boolean enabled,
        Boolean accountLocked,
        Boolean accountExpired,
        Boolean credentialsExpired,

        // --- SECURITY & LOGIN FORENSICS ---
        Integer failedLoginAttempts,
        LocalDateTime lastFailedLogin,
        LocalDateTime lastSuccessfulLogin,
        LocalDateTime lockedUntil,

        // --- COMPLIANCE & LIFECYCLE MANAGEMENT ---
        LocalDateTime accountExpiryDate,       // Contract end date
        LocalDateTime credentialsExpiryDate,   // Password expiration
        LocalDateTime lastPasswordChange,
        boolean mustChangePassword,

        // --- SYSTEM AUDIT TRAIL ---
        LocalDateTime createdAt,
        LocalDateTime updatedAt,
        String createdBy,
        String updatedBy
) {
}