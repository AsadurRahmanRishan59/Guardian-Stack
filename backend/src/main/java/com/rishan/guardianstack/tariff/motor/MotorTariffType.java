package com.rishan.guardianstack.tariff.motor;

public enum MotorTariffType {
    PRIVATE_VEHICLE("Private Vehicle"),
    MOTOR_CYCLE("Motor Cycle"),
    COMMERCIAL_VEHICLE("Commercial Vehicle");

    private final String label;

    MotorTariffType(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    // Optional: get enum from string
    public static MotorTariffType fromLabel(String label) {
        for (MotorTariffType type : MotorTariffType.values()) {
            if (type.label.equalsIgnoreCase(label)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown Motor Tariff type: " + label);
    }
}
