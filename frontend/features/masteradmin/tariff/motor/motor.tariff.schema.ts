import { z } from "zod";

/* Enums (unchanged) */
const MotorTariffType = z.enum([
  "Private Vehicle",
  "Motor Cycle",
  "Commercial Vehicle",
]);

const MotorTariffGroupOfVehicle = z.enum([
  "Passenger Vehicle/Goods Carrying",
  "Trailer",
  "Class A Goods Carrying Vehicles",
  "Class B(1,0) Goods Carrying Vehicles",
  "Class B(1,0) Passenger Carrying Vehicles",
  "Class B(2,0) Passenger Carrying Vehicles",
  "Class C Passenger Carrying Vehicles",
  "Class D Miscellaneous & Special Types of Vehicles",
  "Auto Cycles or Mechanically Assisted Pedal Cycles",
  "MotorCycle/Scooter",
]);

/* Helper: preprocess numeric inputs so:
   - "" / null / undefined => undefined (triggers required_error)
   - numeric string => Number(value)
   - other types pass through (so z.number() can error)
*/
const decimalSchema = (params: {
  min?: number;
  max?: number;
  precision: { precision: number; scale: number };
}) =>
  z.preprocess((val) => {
    if (val === "" || val === null || val === undefined) return undefined;
    if (typeof val === "string") {
      const n = Number(val);
      return Number.isNaN(n) ? val : n;
    }
    return val;
  },
  z.number({
    required_error: "This field is required — enter 0 if none.",
    invalid_type_error: "Must be a valid number",
  })
    .min(params.min ?? -Infinity, { message: `Must be at least ${params.min}` })
    .max(params.max ?? Infinity, { message: `Must be at most ${params.max}` })
    .refine((val) => {
      const [int, dec] = val.toString().split(".");
      return (
        (!int ||
          int.length <=
            params.precision.precision - params.precision.scale) &&
        (!dec || dec.length <= params.precision.scale)
      );
    }, {
      message: `Must have at most ${
        params.precision.precision - params.precision.scale
      } integer digits and ${params.precision.scale} decimal places`,
    })
  );

/* Main schema: required + strict.
   Note: we preprocess enums so "" becomes undefined -> required error.
*/
export const motorTariffRequestFormSchema = z
  .object({
    tariffType: z.preprocess((v) => (v === "" ? undefined : v), MotorTariffType),
    groupOfVehicle: z.preprocess((v) => (v === "" ? undefined : v), MotorTariffGroupOfVehicle),

    typeOfVehicle: z
      .string({ required_error: "Type of vehicle is required" })
      .min(1, "Type of vehicle cannot be blank")
      .max(500, "Type of vehicle must not exceed 500 characters"),

    category: z
      .string({ required_error: "Category is required" })
      .min(1, "Category cannot be blank")
      .max(500, "Category must not exceed 500 characters"),

    ownDpBasic: decimalSchema({
      min: 0,
      max: 50000,
      precision: { precision: 5, scale: 2 },
    }),

    fullInsValue: decimalSchema({
      min: 0,
      max: 100,
      precision: { precision: 3, scale: 2 },
    }),

    actLiability: decimalSchema({
      min: 0,
      max: 10000,
      precision: { precision: 5, scale: 2 },
    }),

    fire: decimalSchema({
      min: 0,
      max: 100,
      precision: { precision: 3, scale: 2 },
    }),

    theft: decimalSchema({
      min: 0,
      max: 100,
      precision: { precision: 3, scale: 2 },
    }),

    cyclone: decimalSchema({
      min: 0,
      max: 100,
      precision: { precision: 3, scale: 2 },
    }),

    earthquake: decimalSchema({
      min: 0,
      max: 100,
      precision: { precision: 3, scale: 2 },
    }),

    others: decimalSchema({
      min: 0,
      max: 100,
      precision: { precision: 3, scale: 2 },
    }),

    // checkbox boolean is ok to coerce; required by schema (no null/undefined allowed)
    isActive: z.coerce.boolean({
      required_error: "Status is required",
      invalid_type_error: "Must be true or false",
    }),
  })
  .strict();

/* Optional: separate patch schema (also strict + required fields) */
export const motorTariffRatesPatchSchema = z
  .object({
    ownDpBasic: decimalSchema({
      min: 0,
      max: 50000,
      precision: { precision: 5, scale: 2 },
    }),
    fullInsValue: decimalSchema({
      min: 0,
      max: 100,
      precision: { precision: 3, scale: 2 },
    }),
    actLiability: decimalSchema({
      min: 0,
      max: 10000,
      precision: { precision: 5, scale: 2 },
    }),
    fire: decimalSchema({
      min: 0,
      max: 100,
      precision: { precision: 3, scale: 2 },
    }),
    theft: decimalSchema({
      min: 0,
      max: 100,
      precision: { precision: 3, scale: 2 },
    }),
    cyclone: decimalSchema({
      min: 0,
      max: 100,
      precision: { precision: 3, scale: 2 },
    }),
    earthquake: decimalSchema({
      min: 0,
      max: 100,
      precision: { precision: 3, scale: 2 },
    }),
    others: decimalSchema({
      min: 0,
      max: 100,
      precision: { precision: 3, scale: 2 },
    }),
  })
  .strict();

export type MotorTariffRequestFormValues = z.infer<
  typeof motorTariffRequestFormSchema
>;
export type MotorTariffRatesPatchFormValues = z.infer<
  typeof motorTariffRatesPatchSchema
>;



const SortByEnum = z.enum(['tariffKey', 'tariffType', 'groupOfVehicle', 'typeOfVehicle', 'category']);
const SortDirectionEnum = z.enum(['asc', 'desc']);

export const motorTariffFilterSchema = z.object({
  // Search
  tariffKey: z.number().int().min(0, "Tariff key must be a non-negative integer").optional(),

  // Hierarchical filters
  tariffType: z.string().optional(),
  groupOfVehicle: z.string().optional(),
  typeOfVehicle: z.string().optional(),
  category: z.string().optional(),

  // Other filters
  isActive: z.boolean().optional(),

  // Pagination with better defaults
  page: z.number().int().min(0, "Page must be non-negative").default(0).optional(),
  size: z.number().int().min(1, "Size must be at least 1").max(100, "Size cannot exceed 100").default(20).optional(),

  // Sorting
  sortBy: SortByEnum.default('tariffKey').optional(),
  sortDirection: SortDirectionEnum.default('asc').optional(),
})

export type MotorTariffFilterFormValues = z.infer<typeof motorTariffFilterSchema>;