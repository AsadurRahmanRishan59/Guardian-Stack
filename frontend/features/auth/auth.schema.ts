import { z } from "zod";

export const loginSchema = z.object({
  username: z
    .string()
    .min(3, "Username must be at least 3 characters")
    .max(20, "Username cannot exceed 20 characters")
    .regex(
      /^(?=.{3,20}$)(?!.*__)[a-zA-Z0-9]+(_[a-zA-Z0-9]+)*$/,
      "Only letters, numbers, underscores. Cannot start or end with underscore"
    ),

  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(120, "Password cannot exceed 120 characters")
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_+=]).{8,120}$/,
      "Password must include uppercase, lowercase, number, and special char"
    ),
});

export type LoginFormData = z.infer<typeof loginSchema>;
