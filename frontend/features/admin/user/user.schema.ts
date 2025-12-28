// features/admin/user/user.schema.ts
import { z } from "zod";
import { SignUpMethod } from "./user.types";

// Filter form schema
export const adminUserViewFilterSchema = z.object({
  username: z.string().optional(),
  enabled: z.boolean().optional(),
  isTwoFactorEnabled: z.boolean().optional(),
  signUpMethod: z.enum(SignUpMethod).optional(),
  roleId: z.number().optional(),
  page: z.number().min(0).optional(),
  size: z.number().min(1).max(100).optional(),
  sortBy: z.string().optional(),
  sortDirection: z.enum(["asc", "desc"]).optional(),
});

export type AdminUserViewFilterFormData = z.infer<typeof adminUserViewFilterSchema>;

// Password validation rules - reusable
const passwordValidation = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .max(120, "Password must not exceed 120 characters")
  .regex(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\\-_=+]).{8,120}$/,
    "Password must include uppercase, lowercase, number, and special character"
  )
  .refine((val) => val.trim() === val, {
    message: "Password cannot contain leading or trailing spaces",
  })
  .refine((val) => val.trim().length > 0, {
    message: "Password cannot be empty or just whitespace",
  })
  .refine((val) => {
    // Common weak passwords to block
    const commonPasswords = [
      "password",
      "12345678",
      "123456789",
      "qwerty123",
      "abc123456",
      "password1",
      "password123",
    ];
    return !commonPasswords.includes(val.toLowerCase());
  }, {
    message: "Password is too common. Please choose a stronger password",
  });

// Unified schema factory function
export const createAdminUserSchema = (isEditMode: boolean) => {
  return z.object({
    username: z
      .string()
      .min(3, "Username must be at least 3 characters")
      .max(20, "Username must not exceed 20 characters")
      .regex(
        /^[a-zA-Z0-9._-]+$/,
        "Username may contain letters, numbers, dots, underscores, and hyphens only"
      ),
    email: z
      .email("Invalid email format")
      .max(50, "Email must not exceed 50 characters"),
    password: z.string(),
    enabled: z.boolean(),
    accountNonExpired: z.boolean(),
    accountNonLocked: z.boolean(),
    credentialsNonExpired: z.boolean(),
    credentialsExpiryDate: z.string().optional(),
    accountExpiryDate: z.string().optional(),
    twoFactorSecret: z.string().max(255).optional(),
    isTwoFactorEnabled: z.boolean(),
    signUpMethod: z.enum(SignUpMethod).optional(),
    roleIds: z.array(z.number().positive()).min(1, "User must have at least one role"),
  }).superRefine((data, ctx) => {
    // Password validation logic based on mode
    if (isEditMode) {
      // EDIT MODE: Password is optional
      // If provided and not empty, validate it
      if (data.password && data.password.trim().length > 0) {
        const result = passwordValidation.safeParse(data.password);
        if (!result.success) {
          result.error.issues.forEach((issue) => {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: issue.message,
              path: ["password"],
            });
          });
        }
      }
      // If empty or just whitespace (but something was entered), reject
      else if (data.password && data.password.length > 0 && data.password.trim().length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Password cannot be just whitespace",
          path: ["password"],
        });
      }
    } else {
      // CREATE MODE: Password is required and must pass validation
      if (!data.password || data.password.trim().length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Password is required for new users",
          path: ["password"],
        });
      } else {
        const result = passwordValidation.safeParse(data.password);
        if (!result.success) {
          result.error.issues.forEach((issue) => {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              message: issue.message,
              path: ["password"],
            });
          });
        }
      }
    }
  });
};

export type AdminUserFormData = z.infer<ReturnType<typeof createAdminUserSchema>>;


// // features/admin/user/user.schema.ts
// import { z } from "zod";


// // Filter form schema
// export const adminUserViewFilterSchema = z.object({
//   username: z.string().optional(),
//   enabled: z.boolean().optional(),
//   isTwoFactorEnabled: z.boolean().optional(),
//   signUpMethod: z.string().optional(),
//   roleId: z.number().optional(),
//   page: z.number().min(0).optional(),
//   size: z.number().min(1).max(100).optional(),
//   sortBy: z.string().optional(),
//   sortDirection: z.enum(["asc", "desc"]).optional(),
// });

// export type AdminUserViewFilterFormData = z.infer<typeof adminUserViewFilterSchema>;

// export const adminUserCreateSchema = z.object({
//   username: z
//     .string()
//     .min(3, "Username must be at least 3 characters")
//     .max(20, "Username must not exceed 20 characters")
//     .regex(
//       /^[a-zA-Z0-9._-]+$/,
//       "Username may contain letters, numbers, dots, underscores, and hyphens only"
//     ),
//   email: z
//     .email("Invalid email format")
//     .max(50, "Email must not exceed 50 characters"),
//   password: z
//     .string()
//     .min(8, "Password must be at least 8 characters")
//     .max(120, "Password must not exceed 120 characters")
//     .regex(
//       /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\\-_=+]).{8,120}$/,
//       "Password must include uppercase, lowercase, number, and special character"
//     ),
//   enabled: z.boolean(),
//   accountNonExpired: z.boolean(),
//   accountNonLocked: z.boolean(),
//   credentialsNonExpired: z.boolean(),
//   credentialsExpiryDate: z.string().optional(),
//   accountExpiryDate: z.string().optional(),
//   twoFactorSecret: z.string().max(255).optional(),
//   isTwoFactorEnabled: z.boolean(),
//   signUpMethod: z.string().max(50).optional(),
//   roleIds: z.array(z.number().positive()).min(1, "User must have at least one role"),
// });

// export type AdminUserCreateFormData = z.infer<typeof adminUserCreateSchema>;