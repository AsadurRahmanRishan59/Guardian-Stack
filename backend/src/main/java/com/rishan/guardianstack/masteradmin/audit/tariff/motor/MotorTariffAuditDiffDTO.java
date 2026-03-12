package com.rishan.guardianstack.masteradmin.audit.tariff.motor;

import lombok.Builder;
import java.util.List;

/**
 * Pre-computed diff between this revision and its predecessor.
 * Backend computes once; frontend renders directly.
 */
@Builder
public record MotorTariffAuditDiffDTO(
        Long             previousRevisionNumber,
        String           previousChangedBy,
        List<DiffField>  changedFields,
        List<DiffField>  unchangedFields,
        boolean          criticalChange    // isActive changed
) {
    @Builder
    public record DiffField(
            String  fieldName,
            String  fieldLabel,
            String  fieldType,      // "BOOLEAN" | "STRING" | "DECIMAL" | "PERCENT"
            String  previousValue,
            String  currentValue,
            boolean critical
    ) {}
}