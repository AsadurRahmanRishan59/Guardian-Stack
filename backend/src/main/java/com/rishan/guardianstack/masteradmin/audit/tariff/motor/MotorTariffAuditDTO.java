package com.rishan.guardianstack.masteradmin.audit.tariff.motor;

import lombok.Builder;
import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * FULL DTO — Powers the Right Rail Inspector Panel.
 * Loaded lazily on node click. Contains full snapshot + pre-computed diff.
 */
@Builder
public record MotorTariffAuditDTO(
        Long                      revisionNumber,
        String                    revisionType,
        LocalDateTime             timestamp,
        String                    changedBy,
        String                    ipAddress,

        // Tariff identity
        Integer                   tariffKey,
        String                    tariffType,
        String                    groupOfVehicle,
        String                    typeOfVehicle,
        String                    category,

        // Financial snapshot at this revision
        BigDecimal                ownDpBasic,
        BigDecimal                fullInsValue,
        BigDecimal                actLiability,
        BigDecimal                fire,
        BigDecimal                theft,
        BigDecimal                cyclone,
        BigDecimal                earthquake,

        Boolean                   isActive,

        MotorTariffAuditDiffDTO   diff   // null only for the very first revision
) {}