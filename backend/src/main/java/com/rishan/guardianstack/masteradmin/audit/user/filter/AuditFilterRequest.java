package com.rishan.guardianstack.masteradmin.audit.user.filter;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * Filter parameters for querying user audit history.
 * All fields are optional — when null/empty they are ignored.
 */
public record AuditFilterRequest(

        // Target user
        Long userId,
        String email,            // partial match, case-insensitive

        // Who made the change
        String changedBy,        // partial match on revinfo.username

        // Network filter
        String ipAddress,        // partial match (supports CIDR-style prefix like "192.168.")

        // Change type filter: ADD, MOD, DEL (maps to revtype 0, 1, 2)
        Set<String> revisionTypes,

        // Date range
        LocalDateTime from,
        LocalDateTime to,

        // Pagination
        int page,
        int size
) {
    // Defaults for page/size
    public AuditFilterRequest {
        if (page < 0) page = 0;
        if (size <= 0 || size > 200) size = 50;
    }
}