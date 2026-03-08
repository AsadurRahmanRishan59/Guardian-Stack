package com.rishan.guardianstack.tariff.motor.dto;

import jakarta.validation.constraints.*;

import java.math.BigDecimal;

public record MotorTariffDTO(
        Integer tariffKey, // Primary key for updates

        @NotBlank(message = "Tariff Type is required (e.g., Private Vehicle, Motor Cycle)")
        @Pattern(regexp = "Private Vehicle|Motor Cycle|Commercial Vehicle", message = "Tariff type must be one of: Private Vehicle, Motor Cycle, Commercial Vehicle")
        @Size(max = 50, message = "Tariff Type must not exceed 50 characters")
        String tariffType,

        @NotBlank(message = "Vehicle Group is required (e.g., Passenger Vehicle)")
        @Size(max = 500, message = "Vehicle Group description is too long")
        String groupOfVehicle,

        @NotBlank(message = "Vehicle Type description is mandatory")
        @Size(max = 500, message = "Vehicle Type description is too long")
        String typeOfVehicle,

        @NotBlank(message = "Category or CC Range must be specified")
        @Size(max = 500, message = "Category description is too long")
        String category,

        @NotNull(message = "Own Damage Basic premium cannot be null")
        @DecimalMin(value = "0.0", message = "Basic premium must be 0 or a positive value")
        @Digits(integer = 8, fraction = 2, message = "Basic premium must be a valid amount (max 8 digits and 2 decimals)")
        BigDecimal ownDpBasic,

        @NotNull(message = "Full Insurance Value rate is required")
        @DecimalMin(value = "0.0", message = "Insurance rate cannot be negative")
        @DecimalMax(value = "100.0", message = "Insurance rate cannot exceed 100%")
        BigDecimal fullInsValue,

        @NotNull(message = "Act Liability fee is mandatory")
        @DecimalMin(value = "0.0", message = "Act Liability cannot be negative")
        BigDecimal actLiability,

        @NotNull(message = "Fire rate (%) is required")
        @DecimalMin(value = "0.0", message = "Fire rate cannot be negative")
        @DecimalMax(value = "100.0", message = "Fire rate cannot exceed 100%")
        BigDecimal fire,

        @NotNull(message = "Theft rate (%) is required")
        @DecimalMin(value = "0.0", message = "Theft rate cannot be negative")
        @DecimalMax(value = "100.0", message = "Theft rate cannot exceed 100%")
        BigDecimal theft,

        @NotNull(message = "Cyclone rate (%) is required")
        @DecimalMin(value = "0.0", message = "Cyclone rate cannot be negative")
        @DecimalMax(value = "100.0", message = "Cyclone rate cannot exceed 100%")
        BigDecimal cyclone,

        @NotNull(message = "Earthquake rate (%) is required")
        @DecimalMin(value = "0.0", message = "Earthquake rate cannot be negative")
        @DecimalMax(value = "100.0", message = "Earthquake rate cannot exceed 100%")
        BigDecimal earthquake,

        @NotNull(message = "Active status must be specified")
        Boolean isActive
) {
}

