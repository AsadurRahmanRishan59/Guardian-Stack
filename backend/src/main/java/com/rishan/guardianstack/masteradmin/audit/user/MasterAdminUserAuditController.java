package com.rishan.guardianstack.masteradmin.audit.user;

import com.rishan.guardianstack.masteradmin.audit.user.filter.AuditFilterRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/v1/master-admin/audit/users")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ROLE_MASTER_ADMIN')")
public class MasterAdminUserAuditController {

    private final MasterAdminUserAuditService auditService;

    // ─────────────────────────────────────────────────────────────────────────
    // GET /api/v1/master-admin/audit/users
    // Paginated, filterable audit log for ALL users
    // ─────────────────────────────────────────────────────────────────────────

    @GetMapping
    public ResponseEntity<Page<MasterAdminUserAuditDTO>> getAuditHistory(

            @RequestParam(required = false) Long userId,

            @RequestParam(required = false) String email,

            @RequestParam(required = false) String changedBy,

            @RequestParam(required = false) String ipAddress,

            @RequestParam(required = false) Set<String> revisionTypes,

            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,

            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,

            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        AuditFilterRequest filter = new AuditFilterRequest(
                userId, email, changedBy, ipAddress, revisionTypes, from, to, page, size
        );

        return ResponseEntity.ok(auditService.getUserAuditHistory(filter));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GET /api/v1/master-admin/audit/users/{userId}
    // Full revision history for a SINGLE user — powers the timeline drill-down
    // ─────────────────────────────────────────────────────────────────────────

    @GetMapping("/{userId}")
    public ResponseEntity<List<MasterAdminUserAuditDTO>> getUserAuditHistory(
            @PathVariable Long userId
    ) {
        return ResponseEntity.ok(auditService.getUserAuditHistoryByUserId(userId));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GET /api/v1/master-admin/audit/users/{userId}/revision/{revisionNumber}
    // Single revision snapshot — powers the Inspector panel on click
    // ─────────────────────────────────────────────────────────────────────────

    @GetMapping("/{userId}/revision/{revisionNumber}")
    public ResponseEntity<MasterAdminUserAuditDTO> getRevisionSnapshot(
            @PathVariable Long userId,
            @PathVariable Long revisionNumber
    ) {
        return auditService.getUserAuditHistoryByUserId(userId).stream()
                .filter(dto -> dto.revisionNumber().equals(revisionNumber))
                .findFirst()
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}