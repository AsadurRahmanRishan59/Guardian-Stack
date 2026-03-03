package com.rishan.guardianstack.masteradmin.audit.user;

import com.rishan.guardianstack.core.response.ApiResponse;
import com.rishan.guardianstack.core.response.PaginatedResponse;
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
    public ResponseEntity<PaginatedResponse<AuditTimelineItemDTO>> getTimelineItems(
            @RequestParam(required = false) Long userId,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) String changedBy,
            @RequestParam(required = false) String ipAddress,
            @RequestParam(required = false) Set<String> revisionTypes,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        Page<AuditTimelineItemDTO> pageResult = auditService.getTimelineItems(
                new AuditFilterRequest(userId, email, changedBy, ipAddress, revisionTypes, from, to, page, size));

        // Mapping Spring Data Page to your custom PaginatedResponse
        return ResponseEntity.ok(PaginatedResponse.of(
                pageResult.getContent(),
                pageResult.getNumber(),
                pageResult.getSize(),
                pageResult.getTotalElements(),
                pageResult.getTotalPages(),
                pageResult.hasNext(),
                pageResult.hasPrevious(),
                "username", // Adjust if you pass sort params
                "desc",
                "Audit history retrieved"
        ));
    }
//    @GetMapping
//    public ResponseEntity<Page<AuditTimelineItemDTO>> getTimelineItems(
//            @RequestParam(required = false) Long userId,
//            @RequestParam(required = false) String email,
//            @RequestParam(required = false) String changedBy,
//            @RequestParam(required = false) String ipAddress,
//            @RequestParam(required = false) Set<String> revisionTypes,
//            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
//            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
//            @RequestParam(defaultValue = "0")  int page,
//            @RequestParam(defaultValue = "50") int size
//    ) {
//        return ResponseEntity.ok(auditService.getTimelineItems(
//                new AuditFilterRequest(userId, email, changedBy, ipAddress, revisionTypes, from, to, page, size)));
//    }

    /** RIGHT PANEL — full detail + diff */
    @GetMapping("/{userId}/revision/{revisionNumber}")
    public ResponseEntity<ApiResponse<MasterAdminUserAuditDTO>> getRevisionDetail(
            @PathVariable Long userId,
            @PathVariable Long revisionNumber) {

        return auditService.getRevisionDetail(userId, revisionNumber)
                .map(dto -> ResponseEntity.ok(new ApiResponse<>(
                        true, "Revision details retrieved", dto, LocalDateTime.now())))
                .orElse(ResponseEntity.notFound().build());
    }

    /** DRILL-DOWN — single user timeline */
    @GetMapping("/{userId}")
    public ResponseEntity<ApiResponse<List<AuditTimelineItemDTO>>> getUserTimeline(
            @PathVariable Long userId) {

        return ResponseEntity.ok(new ApiResponse<>(
                true, "User timeline retrieved", auditService.getUserTimeline(userId), LocalDateTime.now()));
    }
}