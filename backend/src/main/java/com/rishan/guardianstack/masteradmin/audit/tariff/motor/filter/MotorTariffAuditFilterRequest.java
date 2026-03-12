package com.rishan.guardianstack.masteradmin.audit.tariff.motor.filter;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * Filter parameters for querying Motor Tariff audit history.
 * All fields are optional — when null/empty they are ignored.
 */
public record MotorTariffAuditFilterRequest(

        // Target tariff
        Integer tariffKey,
        String  tariffType,      // partial match, case-insensitive

        // Who made the change
        String changedBy,        // partial match on revinfo.username

        // Network filter
        String ipAddress,        // partial match (supports CIDR-style prefix)

        // Change type filter: CREATED, MODIFIED, DELETED
        Set<String> revisionTypes,

        // Date range
        LocalDateTime from,
        LocalDateTime to,

        // Pagination
        int page,
        int size
) {
    public MotorTariffAuditFilterRequest {
        if (page < 0) page = 0;
        if (size <= 0 || size > 200) size = 50;
    }
}