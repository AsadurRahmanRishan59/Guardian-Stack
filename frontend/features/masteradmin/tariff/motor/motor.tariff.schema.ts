import { z } from 'zod';
import { TariffType } from './motor.tariff.types';

export const motorTariffSchema = z.object({
  // v4 allows .int() and .optional() to chain cleanly
  tariffKey: z.number().int().optional(),

  // v4: Use the 'message' property in the params object for enums
  tariffType: z.enum(TariffType, {
    message: "Tariff type must be one of: Private Vehicle, Motor Cycle, Commercial Vehicle",
  }),

  groupOfVehicle: z.string()
    .min(1, "Vehicle Group is required")
    .max(500, "Vehicle Group description is too long"),

  typeOfVehicle: z.string()
    .min(1, "Vehicle Type description is mandatory")
    .max(500, "Vehicle Type description is too long"),

  category: z.string()
    .min(1, "Category or CC Range must be specified")
    .max(500, "Category description is too long"),

  // BigDecimal constraints
  ownDpBasic: z.number()
    .min(0, "Basic premium must be 0 or a positive value")
    .multipleOf(0.01, "Basic premium must have max 2 decimals")
    .max(99999999.99, "Basic premium must be a valid amount (max 8 digits)"),

  fullInsValue: z.number()
    .min(0, "Insurance rate cannot be negative")
    .max(100, "Insurance rate cannot exceed 100%"),

  actLiability: z.number()
    .min(0, "Act Liability cannot be negative"),

  fire: z.number()
    .min(0, "Fire rate cannot be negative")
    .max(100, "Fire rate cannot exceed 100%"),

  theft: z.number()
    .min(0, "Theft rate cannot be negative")
    .max(100, "Theft rate cannot exceed 100%"),

  cyclone: z.number()
    .min(0, "Cyclone rate cannot be negative")
    .max(100, "Cyclone rate cannot exceed 100%"),

  earthquake: z.number()
    .min(0, "Earthquake rate cannot be negative")
    .max(100, "Earthquake rate cannot exceed 100%"),

  // v4: required_error is simplified to 'message' in the params object
  isActive: z.boolean({
    message: "Active status must be specified",
  }),
});

// Extract the TypeScript type from the schema
export type MotorTariffFormValues = z.infer<typeof motorTariffSchema>;