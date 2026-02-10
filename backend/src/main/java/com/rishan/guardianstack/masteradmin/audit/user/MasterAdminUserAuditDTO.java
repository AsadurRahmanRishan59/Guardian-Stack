package com.rishan.guardianstack.masteradmin.audit.user;

import com.rishan.guardianstack.auth.model.SignUpMethod;
import lombok.Builder;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * DTO for User Audit History
 * Contains information about a specific revision/change to a user record
 */
@Builder
public record MasterAdminUserAuditDTO(

        Long revisionNumber,

        //Type of change: ADD (0), MOD (1), DEL (2)
        String revisionType,
        LocalDateTime timestamp,
        String changedBy,
        String ipAddress,

        // =========================================================================
        // SNAPSHOT OF USER DATA AT THIS REVISION
        // =========================================================================
        Long userId,
        String username,
        String email,
        SignUpMethod signUpMethod,
        Set<String> roles,
        Boolean enabled,
        Boolean accountLocked,
        LocalDateTime accountExpiryDate,
        LocalDateTime credentialsExpiryDate,
        LocalDateTime lastPasswordChange
) {
}