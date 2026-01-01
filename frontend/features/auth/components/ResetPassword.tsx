"use client";

import { useSearchParams } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { Lock, Loader2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useResetPassword } from "../auth.react.query";

const resetSchema = z.object({
  email: z.string().email("Invalid email address."),
  otp: z
    .string()
    .length(6, { message: "Your reset code must be exactly 6 characters." }),
  newPassword: z.string().min(8, "Password must be at least 8 characters."),
});

export default function ResetPassword() {
  const searchParams = useSearchParams();
  const emailFromQuery = searchParams.get("email") || "";

  // 1. Initialize the mutation hook
  const { mutate: resetPassword, isPending } = useResetPassword();

  const form = useForm<z.infer<typeof resetSchema>>({
    resolver: zodResolver(resetSchema),
    defaultValues: {
      email: emailFromQuery,
      otp: "",
      newPassword: "",
    },
  });

  // 2. Connect the form to the mutation
  function onSubmit(values: z.infer<typeof resetSchema>) {
    resetPassword(values);
  }

  return (
    <div className="container flex pt-20 flex-col items-center justify-center">
      <Card className="w-full max-w-md dark:bg-slate-950 dark:border-slate-800">
        <CardHeader>
          <CardTitle className="text-2xl font-bold">Reset Password</CardTitle>
          <CardDescription>
            Enter the code sent to{" "}
            <span className="font-semibold text-slate-900 dark:text-slate-100">
              {emailFromQuery || "your email"}
            </span>{" "}
            and set your new password.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              <FormField
                control={form.control}
                name="otp"
                render={({ field }) => (
                  <FormItem className="flex flex-col items-center justify-center space-y-4">
                    <FormLabel>6-Digit Reset Code</FormLabel>
                    <FormControl>
                      <InputOTP maxLength={6} {...field}>
                        <InputOTPGroup className="gap-2">
                          {[...Array(6)].map((_, i) => (
                            <InputOTPSlot
                              key={i}
                              index={i}
                              className="dark:border-slate-700 h-12 w-12 text-lg rounded-md border"
                            />
                          ))}
                        </InputOTPGroup>
                      </InputOTP>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="newPassword"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>New Password</FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Lock className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                        <Input
                          type="password"
                          placeholder="••••••••"
                          className="pl-10 dark:bg-slate-900 border-slate-200 dark:border-slate-800"
                          {...field}
                        />
                      </div>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <Button type="submit" className="w-full" disabled={isPending}>
                {isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {isPending ? "Updating..." : "Change Password"}
              </Button>
            </form>
          </Form>
        </CardContent>
      </Card>
    </div>
  );
}
