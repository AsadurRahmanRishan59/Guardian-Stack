package com.rishan.guardianstack.masteradmin.audit.user;

import com.rishan.guardianstack.masteradmin.audit.user.filter.AuditFilterRequest;
import org.springframework.data.domain.Page;

import java.util.List;

public interface MasterAdminUserAuditService {

    /**
     * Returns paginated audit history for all users, applying optional filters.
     * Results are sorted by revision number DESC.
     */
    Page<MasterAdminUserAuditDTO> getUserAuditHistory(AuditFilterRequest filter);

    /**
     * Returns the full revision history for a single user (no pagination).
     * Used for the timeline view when drilling into one user.
     */
    List<MasterAdminUserAuditDTO> getUserAuditHistoryByUserId(Long userId);
}