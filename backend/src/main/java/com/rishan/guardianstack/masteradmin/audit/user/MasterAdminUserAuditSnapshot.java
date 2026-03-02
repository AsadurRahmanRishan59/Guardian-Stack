package com.rishan.guardianstack.masteradmin.audit.user;

import com.rishan.guardianstack.auth.model.SignUpMethod;
import lombok.Builder;
import java.time.LocalDateTime;
import java.util.Set;

/**
 * Internal projection — used only by AuditDiffMapper and service layer.
 * Never exposed through the API.
 */
@Builder
public record MasterAdminUserAuditSnapshot(
        Long          revisionNumber,
        String        changedBy,
        String        ipAddress,
        LocalDateTime timestamp,
        String        revisionType,
        Long          userId,
        String        username,
        String        email,
        SignUpMethod  signUpMethod,
        Set<String>   roles,
        Boolean       enabled,
        Boolean       accountLocked,
        Boolean       mustChangePassword,
        LocalDateTime accountExpiryDate,
        LocalDateTime credentialsExpiryDate,
        LocalDateTime lastPasswordChange
) {}