// features/masteradmin/user/user.schema.ts
import { z } from "zod";
import { SignUpMethod } from "./user.types";

// ─── Filter schema ────────────────────────────────────────────────────────────

export const masterAdminUserViewFilterSchema = z.object({
  username: z.string().optional(),
  email: z.email().optional(),
  enabled: z.boolean().optional(),
  accountLocked: z.boolean().optional(),
  accountExpired: z.boolean().optional(),
  credentialExpired: z.boolean().optional(),
  signUpMethod: z.enum(SignUpMethod).optional(),
  roleIds: z.array(z.number()).optional(),
  page: z.number().min(0).optional(),
  size: z.number().min(1).max(100).optional(),
  sortBy: z.enum(['userId', 'username', 'createdAt', 'createdBy'] as const).optional(),
  sortDirection: z.enum(["asc", "desc"]).optional(),
});

export type MasterAdminUserViewFilterFormData = z.infer<typeof masterAdminUserViewFilterSchema>;

// ─── Password validation (reusable) ──────────────────────────────────────────

const COMMON_PASSWORDS = [
  "password",
  "12345678",
  "123456789",
  "qwerty123",
  "abc123456",
  "password1",
  "password123",
];

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
  .refine((val) => !COMMON_PASSWORDS.includes(val.toLowerCase()), {
    message: "Password is too common. Please choose a stronger password",
  });

// ─── Unified create / edit schema factory ────────────────────────────────────

export const createMasterAdminUserSchema = (isEditMode: boolean) =>
  z.object({
    username: z
      .string()
      .min(3, "Username must be at least 3 characters")
      .max(255, "Username must not exceed 255 characters")
      .regex(
        /^[a-zA-Z0-9._\- ]+$/,
        "Username may contain letters, numbers, dots, underscores, hyphens, and spaces"
      ),

    email: z
      .email("Invalid email format")
      .max(100, "Email must not exceed 100 characters"),

    password: z.string(), // Password: empty string = "leave unchanged" in edit mode
    roleIds: z.array(z.number().positive()).min(1, "User must have at least one role"),

    enabled: z.boolean(),
    mustChangePassword: z.boolean(),

    // Optional numeric — blank string from <input> is coerced to null
    passwordValidityDays: z
      .union([z.number().int().min(1, "Must be at least 1 day"), z.null()])
      .optional(),

    // Date fields — stored as ISO strings, empty = null
    accountExpiryDate: z.string().optional().nullable(),

    credentialsExpiryDate: z.string().optional().nullable(), // update-only
    lockedUntil: z.string().optional().nullable(),           // update-only
  })

    .superRefine((data, ctx) => {
      // Password validation logic based on mode
      if (isEditMode) {
        // Optional: only validate if the user typed something
        if (data.password && data.password.trim().length > 0) {
          const result = passwordValidation.safeParse(data.password);
          if (!result.success) {
            result.error.issues.forEach((issue) =>
              ctx.addIssue({ ...issue, path: ["password"] })
            );
          }
        }
        // If empty or just whitespace (but something was entered), reject
        else if (
          data.password &&
          data.password.length > 0 &&
          data.password.trim().length === 0
        ) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Password cannot be just whitespace",
            path: ["password"],
          });
        }
      } else {
        // Required in create mode
        if (!data.password || data.password.trim().length === 0) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: "Password is required for new users",
            path: ["password"],
          });
        } else {
          const result = passwordValidation.safeParse(data.password);
          if (!result.success) {
            result.error.issues.forEach((issue) =>
              ctx.addIssue({ ...issue, path: ["password"] })
            );
          }
        }
      }
    });

export type MasterAdminUserFormData = z.infer<ReturnType<typeof createMasterAdminUserSchema>>;