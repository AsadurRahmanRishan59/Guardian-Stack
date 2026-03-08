package com.rishan.guardianstack.tariff.motor.dto;

import java.math.BigDecimal;

public record MotorTariffShortView(
        Integer tariffKey,
        String tariffType,
        String groupOfVehicle,
        String typeOfVehicle,
        String category,
        BigDecimal ownDpBasic,
        BigDecimal fullInsValue,
        BigDecimal actLiability,
        Boolean isActive
) {
}
