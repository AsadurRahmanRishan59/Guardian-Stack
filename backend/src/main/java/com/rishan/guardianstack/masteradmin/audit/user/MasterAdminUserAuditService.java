package com.rishan.guardianstack.masteradmin.audit.user;

import com.rishan.guardianstack.masteradmin.audit.user.filter.AuditFilterRequest;
import org.springframework.data.domain.Page;
import java.util.List;
import java.util.Optional;

public interface MasterAdminUserAuditService {
    /** LEFT PANEL — slim timeline items, paginated */
    Page<AuditTimelineItemDTO> getTimelineItems(AuditFilterRequest filter);

    /** RIGHT PANEL — full detail + diff, loaded on click */
    Optional<MasterAdminUserAuditDTO> getRevisionDetail(Long userId, Long revisionNumber);

    /** DRILL-DOWN — full timeline for one user */
    List<AuditTimelineItemDTO> getUserTimeline(Long userId);
}