import { z } from "zod";


export const signupSchema = z.object({
  username: z.string().min(2, "Name must be at least 2 characters"),
  email: z.string().email("Invalid email address"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(120, "Password is too long")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[a-z]/, "Password must contain at least one lowercase letter")
    .regex(/[0-9]/, "Password must contain at least one digit")
    .regex(/[^A-Za-z0-9]/, "Password must contain at least one special character")
    .refine((val) => !/\s/.test(val), "Password cannot contain spaces"),
  confirmPassword: z.string(),
})
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords do not match",
    path: ["confirmPassword"],
  })
  .refine((data) => !data.password.toLowerCase().includes(data.username.toLowerCase()), {
    message: "Password cannot contain your name",
    path: ["password"],
  });

export type SignupFormData = z.infer<typeof signupSchema>;

export const verifyOtpSchema = z.object({
  otp: z.string().length(6, "Verification code must be 6 digits"),
  email: z.email(),
});

export type VerifyOtpData = z.infer<typeof verifyOtpSchema>;

export const loginSchema = z.object({
  email: z
    .email(),
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


