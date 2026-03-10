
// // Improved type definitions with better constraints
// type MotorTariffHierarchy = typeof motorTariffHierarchy;
// type TariffType = keyof MotorTariffHierarchy;
// type GroupOfVehicle<T extends TariffType> = keyof MotorTariffHierarchy[T];
// type TypeOfVehicle<T extends TariffType, G extends GroupOfVehicle<T>> =
//   keyof MotorTariffHierarchy[T][G];
  
// type Category<
//   T extends TariffType,
//   G extends GroupOfVehicle<T>,
//   V extends TypeOfVehicle<T, G>
// > = MotorTariffHierarchy[T][G][V] extends (infer U)[]
//   ? U extends string[]
//   ? U[number]  // for nested arrays, unwrap one more level
//   : U         // for flat string arrays
//   : never;

// // Enhanced type guards with better error handling
// export function isTariffType(value: unknown): value is TariffType {
//   return typeof value === 'string' && value in motorTariffHierarchy;
// }

// export function isGroupOfVehicle<T extends TariffType>(
//   tariffType: T,
//   value: unknown
// ): value is GroupOfVehicle<T> {
//   return typeof value === 'string' && value in motorTariffHierarchy[tariffType];
// }

// export function isTypeOfVehicle<T extends TariffType, G extends GroupOfVehicle<T>>(
//   tariffType: T,
//   group: G,
//   value: unknown
// ): value is TypeOfVehicle<T, G> {
//   return typeof value === 'string' && value in motorTariffHierarchy[tariffType][group];
// }

// // export function isValidCategory<T extends TariffType, G extends GroupOfVehicle<T>>(
// //   tariffType: T,
// //   group: G,
// //   type: TypeOfVehicle<T, G>,
// //   value: unknown
// // ): value is string {
// //   if (typeof value !== 'string') return false;
// //   const categories = motorTariffHierarchy[tariffType][group][type].flat();
// //   return categories.includes(value);
// // }

// export function isValidCategory<
//   T extends TariffType,
//   G extends GroupOfVehicle<T>,
//   V extends TypeOfVehicle<T, G>
// >(tariffType: T, group: G, type: V, value: unknown): value is Category<T, G, V> {
//   if (typeof value !== 'string') return false;
//   const categories = motorTariffHierarchy[tariffType][group][type].flat();
//   return categories.includes(value);
// }
// // Create the tariff type options array
// const TARIFF_TYPES = ["Private Vehicle", "Motor Cycle", "Commercial Vehicle"] as const;

// // Create enums for better type safety
// const TariffTypeEnum = z.enum(TARIFF_TYPES);
// const SortByEnum = z.enum(['tariffKey', 'tariffType', 'groupOfVehicle', 'typeOfVehicle', 'category']);
// const SortDirectionEnum = z.enum(['asc', 'desc']);

// // Enhanced schema with better validation and error messages
// export const motorTariffFilterSchema = z.object({
//   // Search
//   tariffKey: z.number().int().min(0, "Tariff key must be a non-negative integer").optional(),

//   // Hierarchical filters
//   tariffType: z.string().optional(),
//   groupOfVehicle: z.string().optional(),
//   typeOfVehicle: z.string().optional(),
//   category: z.string().optional(),

//   // Other filters
//   isActive: z.boolean().optional(),

//   // Pagination with better defaults
//   page: z.number().int().min(0, "Page must be non-negative").default(0).optional(),
//   size: z.number().int().min(1, "Size must be at least 1").max(100, "Size cannot exceed 100").default(20).optional(),

//   // Sorting
//   sortBy: SortByEnum.default('tariffKey').optional(),
//   sortDirection: SortDirectionEnum.default('asc').optional(),
// })
//   .superRefine((data, ctx) => {
//     // Enhanced validation with better error messages

//     // Validate tariffType
//     if (data.tariffType && !isTariffType(data.tariffType)) {
//       ctx.addIssue({
//         code: z.ZodIssueCode.custom,
//         message: `Invalid tariff type: "${data.tariffType}". Must be one of: ${Object.keys(motorTariffHierarchy).join(', ')}`,
//         path: ["tariffType"]
//       });
//       return; // Early return to prevent cascading errors
//     }

//     // Validate groupOfVehicle belongs to tariffType
//     if (data.tariffType && data.groupOfVehicle) {
//       const tariffType = data.tariffType as TariffType;

//       if (!isGroupOfVehicle(tariffType, data.groupOfVehicle)) {
//         const validGroups = Object.keys(motorTariffHierarchy[tariffType]);
//         ctx.addIssue({
//           code: z.ZodIssueCode.custom,
//           message: `Group "${data.groupOfVehicle}" is not valid for tariff type "${data.tariffType}". Valid groups: ${validGroups.join(', ')}`,
//           path: ["groupOfVehicle"]
//         });
//         return;
//       }

//       // Validate typeOfVehicle belongs to groupOfVehicle
//       if (data.typeOfVehicle) {
//         const group = data.groupOfVehicle as GroupOfVehicle<typeof tariffType>;

//         if (!isTypeOfVehicle(tariffType, group, data.typeOfVehicle)) {
//           const validTypes = Object.keys(motorTariffHierarchy[tariffType][group]);
//           ctx.addIssue({
//             code: z.ZodIssueCode.custom,
//             message: `Type "${data.typeOfVehicle}" is not valid for group "${data.groupOfVehicle}". Valid types: ${validTypes.join(', ')}`,
//             path: ["typeOfVehicle"]
//           });
//           return;
//         }

//         // Validate category belongs to typeOfVehicle
//         if (data.category) {
//           const type = data.typeOfVehicle as TypeOfVehicle<typeof tariffType, typeof group>;

//           if (!isValidCategory(tariffType, group, type, data.category)) {
//             const validCategories = motorTariffHierarchy[tariffType][group][type].flat();
//             ctx.addIssue({
//               code: z.ZodIssueCode.custom,
//               message: `Category "${data.category}" is not valid for type "${data.typeOfVehicle}". Valid categories: ${validCategories.join(', ')}`,
//               path: ["category"]
//             });
//           }
//         }
//       }
//     }

//     // Validate that dependent fields are not provided without their parents
//     if (data.groupOfVehicle && !data.tariffType) {
//       ctx.addIssue({
//         code: z.ZodIssueCode.custom,
//         message: "Group of vehicle cannot be specified without tariff type",
//         path: ["groupOfVehicle"]
//       });
//     }

//     if (data.typeOfVehicle && (!data.tariffType || !data.groupOfVehicle)) {
//       ctx.addIssue({
//         code: z.ZodIssueCode.custom,
//         message: "Type of vehicle cannot be specified without tariff type and group of vehicle",
//         path: ["typeOfVehicle"]
//       });
//     }

//     if (data.category && (!data.tariffType || !data.groupOfVehicle || !data.typeOfVehicle)) {
//       ctx.addIssue({
//         code: z.ZodIssueCode.custom,
//         message: "Category cannot be specified without tariff type, group of vehicle, and type of vehicle",
//         path: ["category"]
//       });
//     }
//   });

// export type MotorTariffFilterFormValues = z.infer<typeof motorTariffFilterSchema>;

// // Enhanced helper functions with better error handling
// export function getGroupsForTariffType(tariffType: TariffType): GroupOfVehicle<typeof tariffType>[] {
//   if (!isTariffType(tariffType)) {
//     throw new Error(`Invalid tariff type: ${tariffType}`);
//   }
//   return Object.keys(motorTariffHierarchy[tariffType]) as GroupOfVehicle<typeof tariffType>[];
// }

// export function getTypesForGroup<T extends TariffType>(
//   tariffType: T,
//   group: GroupOfVehicle<T>
// ): TypeOfVehicle<T, typeof group>[] {
//   if (!isTariffType(tariffType)) {
//     throw new Error(`Invalid tariff type: ${tariffType}`);
//   }
//   if (!isGroupOfVehicle(tariffType, group)) {
//     throw new Error(`Invalid group: ${String(group)} for tariff type: ${tariffType}`);
//   }

//   const groupData = motorTariffHierarchy[tariffType][group];
//   return Object.keys(groupData) as TypeOfVehicle<T, typeof group>[];
// }

// export function getCategoriesForType<T extends TariffType, G extends GroupOfVehicle<T>>(
//   tariffType: T,
//   group: G,
//   type: TypeOfVehicle<T, G>
// ): string[] {
//   if (!isTariffType(tariffType)) {
//     throw new Error(`Invalid tariff type: ${tariffType}`);
//   }
//   if (!isGroupOfVehicle(tariffType, group)) {
//     throw new Error(`Invalid group: ${String(group)} for tariff type: ${tariffType}`);
//   }
//   if (!isTypeOfVehicle(tariffType, group, type)) {
//     throw new Error(`Invalid type: ${String(type)} for group: ${String(group)}`);
//   }

//   const typeData = motorTariffHierarchy[tariffType][group][type];
//   return typeData.flat();
// }

// // Additional utility functions
// export function getAllTariffTypes(): string[] {
//   return TARIFF_TYPES.slice();
// }

// export function validateHierarchy(
//   tariffType?: string,
//   group?: string,
//   type?: string,
//   category?: string
// ): { isValid: boolean; errors: string[] } {
//   const errors: string[] = [];

//   if (!tariffType) {
//     return { isValid: true, errors: [] };
//   }

//   if (!isTariffType(tariffType)) {
//     errors.push(`Invalid tariff type: ${tariffType}`);
//     return { isValid: false, errors };
//   }

//   if (group && !isGroupOfVehicle(tariffType, group)) {
//     errors.push(`Invalid group: ${group} for tariff type: ${tariffType}`);
//   }

//   if (type && group && isGroupOfVehicle(tariffType, group)) {
//     if (!isTypeOfVehicle(tariffType, group, type)) {
//       errors.push(`Invalid type: ${type} for group: ${group}`);
//     }
//   }

//   if (category && type && group &&
//     isGroupOfVehicle(tariffType, group) &&
//     isTypeOfVehicle(tariffType, group, type)) {
//     if (!isValidCategory(tariffType, group, type, category)) {
//       errors.push(`Invalid category: ${category} for type: ${type}`);
//     }
//   }

//   return { isValid: errors.length === 0, errors };
// }

