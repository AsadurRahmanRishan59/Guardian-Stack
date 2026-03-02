package com.rishan.guardianstack.masteradmin.audit.user;

import lombok.Builder;
import java.time.LocalDateTime;

/**
 * SLIM DTO — Powers the Left Rail Timeline.
 * Only carries the minimum data needed to render a timeline node and
 * decide its visual state (badge color, warning flags, etc.)
 */
@Builder
public record AuditTimelineItemDTO(
        Long          revisionNumber,
        String        revisionType,           // "CREATED" | "MODIFIED" | "DELETED"
        LocalDateTime timestamp,
        String        changedBy,
        String        ipAddress,
        Long          userId,
        String        email,
        boolean       accountLocked,
        boolean       enabled,
        boolean       hasAdminRoleEscalation  // pre-computed: ROLE_ADMIN was added this rev
) {}