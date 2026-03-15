package com.rishan.guardianstack.masteradmin.audit.security;

import com.rishan.guardianstack.core.response.PaginatedResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

/**
 * REST controller for the Security Audit Dashboard.
 *
 * Reads from the manual {@code AuthAuditLog} entity (gs_auth_audit_logs table).
 * Only rows where {@code AuditEventType.shouldPersistToDatabase()} is true are
 * ever written to that table, so every row returned here is already a
 * persistence-worthy security event — no further filtering is needed at the
 * query layer for that rule.
 *
 * Route: GET /master-admin/audit/security
 * Auth:  ROLE_MASTER_ADMIN
 */
@RestController
@RequestMapping("/master-admin/audit/security")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ROLE_MASTER_ADMIN')")
public class SecurityAuditController {

    private final SecurityAuditService securityAuditService;

    /**
     * LEFT PANEL — paginated slim timeline items.
     *
     * Supports filtering by:
     *   ?eventType=LOGIN_FAILED
     *   &userEmail=alice@example.com
     *   &ipAddress=192.168.1.1
     *   &requestId=550e8400-e29b-41d4-a716-446655440000
     *   &success=false
     *   &from=2024-01-01T00:00:00
     *   &to=2024-12-31T23:59:59
     *   &page=0&size=50
     */
    @GetMapping
    public ResponseEntity<PaginatedResponse<SecurityAuditTimelineItemDTO>> getTimelineItems(
            @RequestParam(required = false) String    eventType,
            @RequestParam(required = false) String    userEmail,
            @RequestParam(required = false) String    ipAddress,
            @RequestParam(required = false) String    requestId,
            @RequestParam(required = false) Boolean   success,
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        SecurityAuditFilterRequest filter = new SecurityAuditFilterRequest(
                eventType, userEmail, ipAddress, requestId, success, from, to, page, size);

        Page<SecurityAuditTimelineItemDTO> pageResult =
                securityAuditService.getTimelineItems(filter);

        return ResponseEntity.ok(PaginatedResponse.of(
                pageResult.getContent(),
                pageResult.getNumber(),
                pageResult.getSize(),
                pageResult.getTotalElements(),
                pageResult.getTotalPages(),
                pageResult.hasNext(),
                pageResult.hasPrevious(),
                "timestamp",
                "desc",
                "Security audit log retrieved"));
    }
}