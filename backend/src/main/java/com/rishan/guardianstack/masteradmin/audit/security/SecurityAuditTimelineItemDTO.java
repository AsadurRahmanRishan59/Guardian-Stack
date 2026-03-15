package com.rishan.guardianstack.masteradmin.audit.security;

import java.time.LocalDateTime;

/**
 * Slim DTO surfaced to the left-panel TimelineRail.
 *
 * One instance per {@code AuthAuditLog} row.  Kept deliberately thin so
 * the paginated list query stays fast — no JOINs, no lazy collections.
 *
 * {@code level} is derived server-side from {@code AuditEventType.getLevel()}
 * so the frontend does not need to replicate the enum.
 *
 * {@code requestId} is the per-request UUID written by {@code AuditDbWriter}.
 * It matches the {@code trace.id} field in ELK and the {@code X-Request-ID}
 * HTTP response header, giving the Security Audit Inspector a single
 * correlation handle that spans all three observability layers.
 */
public record SecurityAuditTimelineItemDTO(
        Long          id,
        String        eventType,         // e.g. "LOGIN_FAILED"
        String        eventDescription,  // human-readable from AuditEventType.getDescription()
        String        level,             // DEBUG | INFO | WARN | CRITICAL
        String        userEmail,
        Long          userId,
        String        ipAddress,
        String        userAgent,
        String        requestId,         // correlation UUID — nullable for pre-migration rows
        boolean       success,
        String        failureReason,
        String        additionalInfo,
        LocalDateTime timestamp
) {}