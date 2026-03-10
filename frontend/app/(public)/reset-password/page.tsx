"use client";

// app/(public)/reset-password/page.tsx

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { Lock, ArrowLeft, Loader2 } from "lucide-react";

import {
  Form, FormControl, FormField, FormItem, FormMessage, FormLabel,
} from "@/components/ui/form";
import {
  InputOTP, InputOTPGroup, InputOTPSlot,
} from "@/components/ui/input-otp";
import { useResetPassword } from "@/features/auth/auth.react.query";
import { AuthShell, FIELD_ICON_CLS, LABEL_CLS, BTN_CLS } from "@/components/auth/AuthShell";

const schema = z.object({
  email:       z.string().email(),
  otp:         z.string().length(6, "Code must be exactly 6 digits."),
  newPassword: z.string().min(8, "Password must be at least 8 characters."),
});

export default function ResetPasswordPage() {
  const searchParams   = useSearchParams();
  const emailFromQuery = searchParams.get("email") || "";
  const { mutate: resetPassword, isPending } = useResetPassword();

  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { email: emailFromQuery, otp: "", newPassword: "" },
  });

  return (
    <AuthShell
      heading={"Set your new\npassword."}
      subheading="Enter the 6-digit code from your email and choose a strong new password."
    >
      <div className="mb-7">
        <h2 className="font-head text-[24px] font-extrabold tracking-[-0.025em] text-t1 mb-1">
          New password
        </h2>
        <p className="text-[13.5px] text-t3">
          Didn't get a code?{" "}
          <Link href="/forgot-password" className="font-semibold text-brand hover:text-brand-hover no-underline transition-colors">
            Resend
          </Link>
        </p>
      </div>

      {/* Email context chip */}
      {emailFromQuery && (
        <div className="mb-5 flex items-center gap-2.5 px-3.5 py-2.5 rounded-gs bg-surface-2 border border-gs-line/60">
          <span className="w-2 h-2 rounded-full bg-brand shrink-0" />
          <span className="text-[12.5px] text-t3">
            Sending to <span className="font-semibold text-t1">{emailFromQuery}</span>
          </span>
        </div>
      )}

      <Form {...form}>
        <form onSubmit={form.handleSubmit((d) => resetPassword(d))} className="space-y-5">

          {/* OTP */}
          <FormField control={form.control} name="otp" render={({ field }) => (
            <FormItem>
              <FormLabel className={LABEL_CLS}>6-digit verification code</FormLabel>
              <FormControl>
                <InputOTP maxLength={6} {...field}>
                  <InputOTPGroup className="gap-2 w-full">
                    {[...Array(6)].map((_, i) => (
                      <InputOTPSlot
                        key={i}
                        index={i}
                        className="
                          flex-1 h-12 text-[18px] font-bold
                          border border-gs-line rounded-gs-sm
                          bg-surface text-t1
                          focus:border-brand focus:ring-2 focus:ring-brand/10
                          transition-all duration-150
                        "
                      />
                    ))}
                  </InputOTPGroup>
                </InputOTP>
              </FormControl>
              <FormMessage className="text-[11.5px] text-red-500 mt-1" />
            </FormItem>
          )} />

          {/* New password */}
          <FormField control={form.control} name="newPassword" render={({ field }) => (
            <FormItem>
              <label className={LABEL_CLS}>New password</label>
              <FormControl>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-t4 pointer-events-none" />
                  <input
                    type="password"
                    placeholder="8+ characters"
                    className={FIELD_ICON_CLS}
                    disabled={isPending}
                    {...field}
                  />
                </div>
              </FormControl>
              <FormMessage className="text-[11.5px] text-red-500 mt-1" />
            </FormItem>
          )} />

          <button type="submit" className={BTN_CLS} disabled={isPending}>
            {isPending
              ? <><Loader2 className="w-4 h-4 animate-spin" /> Updating…</>
              : "Update password"
            }
          </button>
        </form>
      </Form>

      <div className="mt-6 flex justify-center">
        <Link
          href="/signin"
          className="inline-flex items-center gap-1.5 text-[12.5px] font-medium text-t3 hover:text-t1 no-underline transition-colors group"
        >
          <ArrowLeft className="w-3.5 h-3.5 transition-transform group-hover:-translate-x-0.5" />
          Back to sign in
        </Link>
      </div>

      <p className="mt-8 text-center text-[11.5px] text-t4">
        © {new Date().getFullYear()} Guardian Stack Insurance Group
      </p>
    </AuthShell>
  );
}