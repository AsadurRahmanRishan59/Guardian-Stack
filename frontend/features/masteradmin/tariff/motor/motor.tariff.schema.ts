import { z } from "zod";

export const motorTariffSchema = z.object({
  tariffKey: z.number().optional(),

  tariffType: z
    .string()
    .min(1, "Tariff Type is required (e.g., Private Vehicle, Motor Cycle)")
    .max(50, "Tariff Type must not exceed 50 characters")
    .regex(
      /^(Private Vehicle|Motor Cycle|Commercial Vehicle)$/,
      "Tariff type must be one of: Private Vehicle, Motor Cycle, Commercial Vehicle"
    ),

  groupOfVehicle: z
    .string()
    .min(1, "Vehicle Group is required")
    .max(500, "Vehicle Group description is too long"),

  typeOfVehicle: z
    .string()
    .min(1, "Vehicle Type description is mandatory")
    .max(500, "Vehicle Type description is too long"),

  category: z
    .string()
    .min(1, "Category or CC Range must be specified")
    .max(500, "Category description is too long"),

  ownDpBasic: z.coerce.number().min(0, "Basic premium must be 0 or a positive value"),

  fullInsValue: z.coerce.number().min(0, "Insurance rate cannot be negative").max(100, "Insurance rate cannot exceed 100%"),

  actLiability: z.coerce.number().min(0, "Act Liability cannot be negative"),

  fire: z.coerce.number().min(0, "Fire rate cannot be negative").max(100, "Fire rate cannot exceed 100%"),

  theft: z.coerce.number().min(0, "Theft rate cannot be negative").max(100, "Theft rate cannot exceed 100%"),

  cyclone: z.coerce.number().min(0, "Cyclone rate cannot be negative").max(100, "Cyclone rate cannot exceed 100%"),

  earthquake: z.coerce.number().min(0, "Earthquake rate cannot be negative").max(100, "Earthquake rate cannot exceed 100%"),

  isActive: z.boolean(),
});

export type MotorTariffFormValues = {
  tariffKey?: number;
  tariffType: string;
  groupOfVehicle: string;
  typeOfVehicle: string;
  category: string;
  ownDpBasic: number;
  fullInsValue: number;
  actLiability: number;
  fire: number;
  theft: number;
  cyclone: number;
  earthquake: number;
  isActive: boolean;
};


export const motorTariffFilterSchema = z.object({
  // Search
  tariffKey: z.coerce
    .number()
    .min(1, "Tariff Key must be a positive number")
    .optional(),

  // Filters
  tariffType: z.string().optional(),
  groupOfVehicle: z.string().optional(),
  typeOfVehicle: z.string().optional(),
  category: z.string().optional(),
  isActive: z.coerce.boolean().optional(),

  // Pagination
  page: z.coerce
    .number()
    .min(0, "Page number must be non-negative")
    .default(0),

  size: z.coerce
    .number()
    .min(1, "Page size must be at least 1")
    .default(10),

  // Sorting
  sortBy: z
    .enum([
      "tariffKey",
      "tariffType",
      "groupOfVehicle",
      "typeOfVehicle",
      "category",
    ])
    .default("tariffKey"),

  sortDirection: z.enum(["asc", "desc"]).default("asc"),
});

export type MotorTariffFilterFormValues = z.infer<
  typeof motorTariffFilterSchema
>;