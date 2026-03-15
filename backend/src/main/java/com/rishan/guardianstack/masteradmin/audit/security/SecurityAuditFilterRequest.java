package com.rishan.guardianstack.masteradmin.audit.security;

import java.time.LocalDateTime;

/**
 * Immutable filter bag passed from the controller to the service/repository layer.
 *
 * All fields are nullable — a null field means "no filter on this dimension".
 *
 * requestId supports exact-match lookup: an ops engineer can paste the UUID
 * from browser dev-tools (X-Request-ID header) or an ELK trace.id to locate
 * the exact row instantly.
 */
public record SecurityAuditFilterRequest(
        String        eventType,   // matches AuditEventType enum name exactly
        String        userEmail,
        String        ipAddress,
        String        requestId,   // exact UUID match — links to ELK trace.id
        Boolean       success,     // null → both; true → only successes; false → only failures
        LocalDateTime from,
        LocalDateTime to,
        int           page,
        int           size
) {}