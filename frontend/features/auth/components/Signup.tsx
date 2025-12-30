"use client";

import { useState, useMemo } from "react";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import { Eye, EyeOff, ShieldCheck, AlertCircle } from "lucide-react";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useSignup } from "../auth.react.query";
import { SignupFormData, signupSchema } from "../auth.schema";
import { isServerError } from "@/lib/api/error-handling";

const Requirement = ({ met, text }: { met: boolean; text: string }) => (
  <div className="flex items-center gap-2 transition-all duration-300">
    <div
      className={`h-1.5 w-1.5 rounded-full ${
        met
          ? "bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]"
          : "bg-slate-300 dark:bg-slate-600"
      }`}
    />
    <span
      className={`text-[11px] ${
        met
          ? "text-green-600 dark:text-green-400 font-medium"
          : "text-slate-500 dark:text-slate-500"
      }`}
    >
      {text}
    </span>
  </div>
);

export default function SignUpForm() {
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  // mutateAsync allows us to use the try-catch block for custom error mapping
  const { mutateAsync: signup, isPending } = useSignup();

  const form = useForm<SignupFormData>({
    resolver: zodResolver(signupSchema),
    defaultValues: {
      username: "",
      email: "",
      password: "",
      confirmPassword: "",
    },
  });

  const password = useWatch({ control: form.control, name: "password" }) || "";
  const username = useWatch({ control: form.control, name: "username" }) || "";

  // 1. Smart Name Detection & Policy Logic
  const checks = useMemo(() => {
    const pwdLower = password.toLowerCase();
    const nameParts = username
      .toLowerCase()
      .split(/\s+/)
      .filter((p) => p.length > 2);

    return {
      length: password.length >= 8,
      upper: /[A-Z]/.test(password),
      lower: /[a-z]/.test(password),
      number: /[0-9]/.test(password),
      special: /[^A-Za-z0-9]/.test(password),
      noName:
        username.length > 0 &&
        !nameParts.some((part) => pwdLower.includes(part)),
    };
  }, [password, username]);

  const allMet = Object.values(checks).every(Boolean);

  // 2. Submit Logic with your custom Error Handler pattern
  const onSubmit = async (values: SignupFormData) => {
    try {
      const signupData = {
        username: values.username,
        email: values.email,
        password: values.password,
      };
      await signup(signupData);
      form.reset();
    } catch (error) {
      if (isServerError(error)) {
        if (error.data && typeof error.data === "object") {
          const dataObj = error.data as Record<string, string>;
          Object.entries(dataObj).forEach(([field, message]) => {
            // Map backend field names (e.g. "password") to form fields
            if (field in form.getValues()) {
              form.setError(field as keyof SignupFormData, {
                type: "server",
                message: message,
              });
            }
          });

          if (Object.keys(dataObj).length === 0) {
            form.setError("root.serverError", {
              type: "server",
              message:
                typeof error.message === "string"
                  ? error.message
                  : "Registration failed",
            });
          }
        }
      } else {
        form.setError("root.serverError", {
          type: "server",
          message: "An unexpected network error occurred.",
        });
      }
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50 p-4 dark:bg-slate-950">
      <Card className="w-full max-w-md border-gray-200 dark:border-slate-800 dark:bg-slate-900 shadow-xl">
        <CardHeader className="space-y-1 text-center">
          <div className="flex justify-center mb-2">
            <ShieldCheck className="w-10 h-10 text-blue-600" />
          </div>
          <CardTitle className="text-2xl font-bold dark:text-white">
            GuardianStack
          </CardTitle>
          <CardDescription>Secure Infrastructure Registration</CardDescription>
        </CardHeader>

        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              {/* Root Server Error Alert */}
              {form.formState.errors.root?.serverError && (
                <div className="flex items-center gap-2 p-3 rounded-md bg-destructive/10 border border-destructive/20 text-destructive text-xs animate-in fade-in zoom-in">
                  <AlertCircle size={16} />
                  {form.formState.errors.root.serverError.message}
                </div>
              )}

              <FormField
                control={form.control}
                name="username"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Full Name</FormLabel>
                    <FormControl>
                      <Input placeholder="John Doe" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="email"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Corporate Email</FormLabel>
                    <FormControl>
                      <Input
                        type="email"
                        placeholder="john@company.com"
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <div className="space-y-3">
                <FormField
                  control={form.control}
                  name="password"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Password</FormLabel>
                      <FormControl>
                        <div className="relative">
                          <Input
                            type={showPassword ? "text" : "password"}
                            {...field}
                            className="pr-10"
                          />
                          <button
                            type="button"
                            onClick={() => setShowPassword(!showPassword)}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                          >
                            {showPassword ? (
                              <EyeOff size={16} />
                            ) : (
                              <Eye size={16} />
                            )}
                          </button>
                        </div>
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                {/* Real-time Checklist */}
                <div className="grid grid-cols-2 gap-2 rounded-lg border border-slate-100 bg-slate-50/50 p-3 dark:border-slate-800 dark:bg-slate-800/50">
                  <Requirement met={checks.length} text="8+ Characters" />
                  <Requirement met={checks.upper} text="Uppercase" />
                  <Requirement met={checks.lower} text="Lowercase" />
                  <Requirement met={checks.number} text="Number" />
                  <Requirement met={checks.special} text="Symbol" />
                  <Requirement met={checks.noName} text="No name parts" />
                </div>
              </div>

              <FormField
                control={form.control}
                name="confirmPassword"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Confirm Password</FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Input
                          type={showConfirmPassword ? "text" : "password"}
                          {...field}
                          className="pr-10"
                        />
                        <button
                          type="button"
                          onClick={() =>
                            setShowConfirmPassword(!showConfirmPassword)
                          }
                          className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400"
                        >
                          {showConfirmPassword ? (
                            <EyeOff size={16} />
                          ) : (
                            <Eye size={16} />
                          )}
                        </button>
                      </div>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <Button
                type="submit"
                disabled={!allMet || isPending}
                className={`w-full ${
                  allMet
                    ? "bg-blue-600 hover:bg-blue-700"
                    : "bg-slate-300 dark:bg-slate-800"
                }`}
              >
                {isPending ? "Creating Account..." : "Create Account"}
              </Button>
            </form>
          </Form>

          <div className="mt-4 text-center text-sm text-slate-500">
            Already have an account?{" "}
            <Link href="/login" className="text-blue-600 hover:underline">
              Sign In
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
