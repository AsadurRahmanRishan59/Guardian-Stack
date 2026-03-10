"use client";

// app/(public)/verify-otp/page.tsx

import Link from "next/link";
import { useSearchParams, useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useState, useEffect } from "react";
import { ArrowLeft, RefreshCw, Loader2 } from "lucide-react";

import {
  Form, FormControl, FormField, FormItem, FormMessage, FormLabel,
} from "@/components/ui/form";
import {
  InputOTP, InputOTPGroup, InputOTPSlot,
} from "@/components/ui/input-otp";
import { useVerifyOtp, useResendOtp } from "@/features/auth/auth.react.query";
import { verifyOtpSchema, VerifyOtpData } from "@/features/auth/auth.schema";
import { isServerError } from "@/lib/api/error-handling";
import { AuthShell, BTN_CLS, LABEL_CLS } from "@/components/auth/AuthShell";

export default function VerifyOtpPage() {
  const searchParams = useSearchParams();
  const router       = useRouter();
  const email        = searchParams.get("email") || "";

  const { mutateAsync: verify, isPending }      = useVerifyOtp();
  const { mutate: resend, isPending: isResending } = useResendOtp();

  const [timer, setTimer] = useState(60);

  useEffect(() => {
    if (timer === 0) return;
    const id = setInterval(() => setTimer((t) => (t > 0 ? t - 1 : 0)), 1000);
    return () => clearInterval(id);
  }, [timer]);

  const form = useForm<VerifyOtpData>({
    resolver: zodResolver(verifyOtpSchema),
    defaultValues: { otp: "", email },
  });

  const onSubmit = async (values: VerifyOtpData) => {
    try {
      await verify(values);
      router.push("/dashboard");
    } catch (error) {
      if (isServerError(error)) {
        form.setError("otp", {
          type: "server",
          message: typeof error.message === "string" ? error.message : "Incorrect code. Please try again.",
        });
      }
    }
  };

  return (
    <AuthShell
      heading={"Verify your\nemail address."}
      subheading="We sent a 6-digit code to your email. Enter it below to complete your registration."
    >
      <div className="mb-7">
        <h2 className="font-head text-[24px] font-extrabold tracking-[-0.025em] text-t1 mb-1">
          Enter your code
        </h2>
        <p className="text-[13.5px] text-t3">
          Final step to secure your account.
        </p>
      </div>

      {/* Email context chip */}
      {email && (
        <div className="mb-6 flex items-center gap-2.5 px-3.5 py-2.5 rounded-gs bg-surface-2 border border-gs-line/60">
          <span className="w-2 h-2 rounded-full bg-brand shrink-0" />
          <span className="text-[12.5px] text-t3">
            Code sent to <span className="font-semibold text-t1 break-all">{email}</span>
          </span>
        </div>
      )}

      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-5">

          {/* OTP input */}
          <FormField control={form.control} name="otp" render={({ field }) => (
            <FormItem>
              <FormLabel className={LABEL_CLS}>Verification code</FormLabel>
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

          <button type="submit" className={BTN_CLS} disabled={isPending}>
            {isPending
              ? <><Loader2 className="w-4 h-4 animate-spin" /> Verifying…</>
              : "Complete registration"
            }
          </button>
        </form>
      </Form>

      {/* Resend row */}
      <div className="mt-5 text-center text-[13px] text-t3">
        Didn't receive it?{" "}
        {timer > 0 ? (
          <span className="text-t4 font-medium">Retry in {timer}s</span>
        ) : (
          <button
            type="button"
            onClick={() => { resend({ email }); setTimer(60); }}
            disabled={isResending}
            className="inline-flex items-center gap-1.5 font-semibold text-brand hover:text-brand-hover transition-colors bg-transparent border-none cursor-pointer p-0"
          >
            {isResending && <RefreshCw className="w-3 h-3 animate-spin" />}
            Send new code
          </button>
        )}
      </div>

      <div className="mt-6 flex justify-center">
        <Link
          href="/signup"
          className="inline-flex items-center gap-1.5 text-[12.5px] font-medium text-t3 hover:text-t1 no-underline transition-colors group"
        >
          <ArrowLeft className="w-3.5 h-3.5 transition-transform group-hover:-translate-x-0.5" />
          Back to sign up
        </Link>
      </div>

      <p className="mt-8 text-center text-[11.5px] text-t4">
        © {new Date().getFullYear()} Guardian Stack Insurance Group
      </p>
    </AuthShell>
  );
}