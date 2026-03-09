package com.rishan.guardianstack.tariff.motor;

public enum MotorHierarchyLevel {
    TARIFF_TYPE, GROUP_OF_VEHICLE, TYPE_OF_VEHICLE, CATEGORY;

    public static MotorHierarchyLevel fromString(String level) {
        return switch (level) {
            case "tariffType" -> TARIFF_TYPE;
            case "groupOfVehicle" -> GROUP_OF_VEHICLE;
            case "typeOfVehicle" -> TYPE_OF_VEHICLE;
            case "category" -> CATEGORY;
            default -> throw new IllegalArgumentException("Invalid level: " + level);
        };
    }
}