package com.rishan.guardianstack.masteradmin.audit.user;

import lombok.Builder;
import java.util.List;
import java.util.Set;

/**
 * Pre-computed diff between this revision and its predecessor.
 * Backend computes once; frontend renders directly — no index+1 needed in UI.
 */
@Builder
public record AuditDiffDTO(
        Long             previousRevisionNumber,
        String           previousChangedBy,
        List<DiffField>  changedFields,
        List<DiffField>  unchangedFields,
        Set<String>      addedRoles,
        Set<String>      removedRoles,
        boolean          criticalChange,    // accountLocked or enabled changed
        boolean          adminEscalation    // ROLE_ADMIN was added
) {
    @Builder
    public record DiffField(
            String  fieldName,
            String  fieldLabel,
            String  fieldType,      // "BOOLEAN" | "STRING" | "ROLES" | "DATETIME"
            String  previousValue,
            String  currentValue,
            boolean critical
    ) {}
}