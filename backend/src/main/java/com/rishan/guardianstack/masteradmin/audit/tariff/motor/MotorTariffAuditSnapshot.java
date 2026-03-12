package com.rishan.guardianstack.masteradmin.audit.tariff.motor;

import lombok.Builder;
import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Internal projection — used only by MotorTariffAuditDiffMapper and service layer.
 * Never exposed through the API.
 */
@Builder
public record MotorTariffAuditSnapshot(
        Long          revisionNumber,
        String        changedBy,
        String        ipAddress,
        LocalDateTime timestamp,
        String        revisionType,

        // Identity
        Integer       tariffKey,
        String        tariffType,
        String        groupOfVehicle,
        String        typeOfVehicle,
        String        category,

        // Financial
        BigDecimal    ownDpBasic,
        BigDecimal    fullInsValue,
        BigDecimal    actLiability,

        // Rates
        BigDecimal    fire,
        BigDecimal    theft,
        BigDecimal    cyclone,
        BigDecimal    earthquake,

        // Status
        Boolean       isActive
) {}