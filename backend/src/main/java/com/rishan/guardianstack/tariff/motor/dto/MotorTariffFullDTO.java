package com.rishan.guardianstack.tariff.motor.dto;

import java.math.BigDecimal;
import java.time.LocalDateTime;

public record MotorTariffFullDTO(
        Integer tariffKey,
        String tariffType,
        String groupOfVehicle,
        String typeOfVehicle,
        String category,
        BigDecimal ownDpBasic,
        BigDecimal fullInsValue,
        BigDecimal actLiability,
        BigDecimal fire,
        BigDecimal theft,
        BigDecimal cyclone,
        BigDecimal earthquake,
        Boolean isActive,
        LocalDateTime createdAt,
        LocalDateTime updatedAt,
        String createdBy,
        String updatedBy
) {
}
