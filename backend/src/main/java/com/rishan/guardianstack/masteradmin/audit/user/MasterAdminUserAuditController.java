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
@RequestMapping("/master-admin/audit/users")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ROLE_MASTER_ADMIN')")
public class MasterAdminUserAuditController {

    private final MasterAdminUserAuditService auditService;

    /** LEFT PANEL — slim timeline items */
    @GetMapping
    public ResponseEntity<Page<AuditTimelineItemDTO>> getTimelineItems(
            @RequestParam(required = false) Long userId,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String changedBy,
            @RequestParam(required = false) String ipAddress,
            @RequestParam(required = false) Set<String> revisionTypes,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        return ResponseEntity.ok(auditService.getTimelineItems(
                new AuditFilterRequest(userId, email, changedBy, ipAddress, revisionTypes, from, to, page, size)));
    }

    /** RIGHT PANEL — full detail + diff */
    @GetMapping("/{userId}/revision/{revisionNumber}")
    public ResponseEntity<MasterAdminUserAuditDTO> getRevisionDetail(
            @PathVariable Long userId, @PathVariable Long revisionNumber) {
        return auditService.getRevisionDetail(userId, revisionNumber)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /** DRILL-DOWN — single user timeline */
    @GetMapping("/{userId}")
    public ResponseEntity<List<AuditTimelineItemDTO>> getUserTimeline(@PathVariable Long userId) {
        return ResponseEntity.ok(auditService.getUserTimeline(userId));
    }
}