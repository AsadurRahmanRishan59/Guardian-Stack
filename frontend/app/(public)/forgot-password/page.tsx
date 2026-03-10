"use client";

// app/(public)/forgot-password/page.tsx

import Link from "next/link";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { Mail, ArrowLeft, Loader2 } from "lucide-react";

import { Form, FormControl, FormField, FormItem, FormMessage } from "@/components/ui/form";
import { useForgotPassword } from "@/features/auth/auth.react.query";
import { AuthShell, FIELD_ICON_CLS, LABEL_CLS, BTN_CLS } from "@/components/auth/AuthShell";

const schema = z.object({
  email: z.string().email("Please enter a valid email address."),
});

export default function ForgotPasswordPage() {
  const { mutate: forgotPassword, isPending, isSuccess } = useForgotPassword();

  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { email: "" },
  });

  return (
    <AuthShell
      heading={"Forgot your\npassword?"}
      subheading="No worries — enter your email and we'll send you a 6-digit reset code within seconds."
    >
      <div className="mb-7">
        <h2 className="font-head text-[24px] font-extrabold tracking-[-0.025em] text-t1 mb-1">
          Reset password
        </h2>
        <p className="text-[13.5px] text-t3">
          Remembered it?{" "}
          <Link href="/signin" className="font-semibold text-brand hover:text-brand-hover no-underline transition-colors">
            Sign in
          </Link>
        </p>
      </div>

      {isSuccess ? (
        /* ── Success state ─────────────────────────────────────────────────── */
        <div className="rounded-gs border border-gs-green/30 bg-gs-green-bg p-5 text-center animate-fade-up">
          <div className="w-10 h-10 rounded-full bg-gs-green/15 flex items-center justify-center mx-auto mb-3">
            <svg className="w-5 h-5 text-gs-green" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <p className="font-semibold text-[14px] text-t1 mb-1">Check your inbox</p>
          <p className="text-[13px] text-t3 leading-relaxed">
            We've sent a reset code to your email. It expires in 10 minutes.
          </p>
          <Link
            href="/reset-password"
            className="
              inline-flex items-center justify-center mt-5
              h-10 px-6 rounded-gs
              bg-brand hover:bg-brand-hover
              text-white text-[13px] font-semibold no-underline
              transition-all duration-150
            "
          >
            Enter reset code →
          </Link>
        </div>
      ) : (
        /* ── Form ─────────────────────────────────────────────────────────── */
        <>
          <div className="mb-5 p-4 rounded-gs bg-surface-2 border border-gs-line/60 text-[13px] text-t3 leading-relaxed">
            Enter the email address on your account. We'll send a 6-digit code to reset your password.
          </div>

          <Form {...form}>
            <form onSubmit={form.handleSubmit((d) => forgotPassword({ email: d.email }))} className="space-y-4">
              <FormField control={form.control} name="email" render={({ field }) => (
                <FormItem>
                  <label className={LABEL_CLS}>Email address</label>
                  <FormControl>
                    <div className="relative">
                      <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-t4 pointer-events-none" />
                      <input
                        type="email"
                        placeholder="you@example.com"
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
                  ? <><Loader2 className="w-4 h-4 animate-spin" /> Sending…</>
                  : "Send reset code"
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
        </>
      )}

      <p className="mt-8 text-center text-[11.5px] text-t4">
        © {new Date().getFullYear()} Guardian Stack Insurance Group
      </p>
    </AuthShell>
  );
}