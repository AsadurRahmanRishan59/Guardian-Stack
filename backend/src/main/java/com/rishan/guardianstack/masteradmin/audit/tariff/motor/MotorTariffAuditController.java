package com.rishan.guardianstack.masteradmin.audit.tariff.motor;

import com.rishan.guardianstack.core.response.ApiResponse;
import com.rishan.guardianstack.core.response.PaginatedResponse;
import com.rishan.guardianstack.masteradmin.audit.tariff.motor.filter.MotorTariffAuditFilterRequest;
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
@RequestMapping("/master-admin/audit/tariffs/motor")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ROLE_MASTER_ADMIN')")
public class MotorTariffAuditController {

    private final MotorTariffAuditService auditService;

    /**
     * LEFT PANEL — paginated slim timeline items.
     *
     * GET /master-admin/audit/tariffs/motor
     *   ?tariffKey=1&tariffType=Private+Vehicle&changedBy=admin
     *   &revisionTypes=CREATED&revisionTypes=MODIFIED
     *   &from=2024-01-01T00:00:00&to=2024-12-31T23:59:59
     *   &page=0&size=50
     */
    @GetMapping
    public ResponseEntity<PaginatedResponse<MotorTariffAuditTimelineItemDTO>> getTimelineItems(
            @RequestParam(required = false) Integer tariffKey,
            @RequestParam(required = false) String  tariffType,
            @RequestParam(required = false) String  changedBy,
            @RequestParam(required = false) String  ipAddress,
            @RequestParam(required = false) Set<String> revisionTypes,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        Page<MotorTariffAuditTimelineItemDTO> pageResult = auditService.getTimelineItems(
                new MotorTariffAuditFilterRequest(
                        tariffKey, tariffType, changedBy, ipAddress,
                        revisionTypes, from, to, page, size));

        return ResponseEntity.ok(PaginatedResponse.of(
                pageResult.getContent(),
                pageResult.getNumber(),
                pageResult.getSize(),
                pageResult.getTotalElements(),
                pageResult.getTotalPages(),
                pageResult.hasNext(),
                pageResult.hasPrevious(),
                "revisionNumber",
                "desc",
                "Motor tariff audit history retrieved"));
    }

    /**
     * RIGHT PANEL — full snapshot + diff for one revision.
     *
     * GET /master-admin/audit/tariffs/motor/{tariffKey}/revision/{revisionNumber}
     */
    @GetMapping("/{tariffKey}/revision/{revisionNumber}")
    public ResponseEntity<ApiResponse<MotorTariffAuditDTO>> getRevisionDetail(
            @PathVariable Integer tariffKey,
            @PathVariable Long    revisionNumber) {

        return auditService.getRevisionDetail(tariffKey, revisionNumber)
                .map(dto -> ResponseEntity.ok(new ApiResponse<>(
                        true, "Revision details retrieved", dto, LocalDateTime.now())))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * DRILL-DOWN — full history for a single tariff entry.
     *
     * GET /master-admin/audit/tariffs/motor/{tariffKey}
     */
    @GetMapping("/{tariffKey}")
    public ResponseEntity<ApiResponse<List<MotorTariffAuditTimelineItemDTO>>> getTariffTimeline(
            @PathVariable Integer tariffKey) {

        return ResponseEntity.ok(new ApiResponse<>(
                true,
                "Tariff timeline retrieved",
                auditService.getTariffTimeline(tariffKey),
                LocalDateTime.now()));
    }
}