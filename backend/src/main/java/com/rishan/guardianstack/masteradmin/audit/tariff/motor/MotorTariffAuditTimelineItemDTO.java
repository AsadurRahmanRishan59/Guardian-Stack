package com.rishan.guardianstack.masteradmin.audit.tariff.motor;

import lombok.Builder;
import java.time.LocalDateTime;

/**
 * Slim DTO — one entry per timeline node in the left panel.
 * Loaded in bulk; contains only what the timeline node needs to render.
 */
@Builder
public record MotorTariffAuditTimelineItemDTO(
        Long          revisionNumber,
        String        revisionType,
        LocalDateTime timestamp,
        String        changedBy,
        String        ipAddress,

        // Tariff identity (shown on the node)
        Integer       tariffKey,
        String        tariffType,
        String        groupOfVehicle,
        String        typeOfVehicle,
        String        category,

        // Status indicators
        boolean       isActive,
        boolean       statusChanged      // pre-computed: isActive changed vs predecessor
) {}