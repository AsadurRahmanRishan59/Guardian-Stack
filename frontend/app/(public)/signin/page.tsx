"use client";

// app/(public)/signin/page.tsx

import Link from "next/link";
import { useSignin } from "@/features/auth/auth.react.query";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { Clock, Loader2, Lock, LogOut, Mail } from "lucide-react";
import { useSearchParams } from "next/navigation";

import { Form, FormControl, FormField, FormItem, FormMessage } from "@/components/ui/form";
import { loginSchema, LoginFormData } from "@/features/auth/auth.schema";
import { AuthShell, FIELD_ICON_CLS, LABEL_CLS, BTN_CLS } from "@/components/auth/AuthShell";

// ─── Session alert ────────────────────────────────────────────────────────────

function SessionAlert({ errorType }: { errorType: string | null }) {
  if (!errorType) return null;

  const alerts: Record<string, { title: string; desc: string; icon: React.ReactNode; cls: string }> = {
    displaced: {
      title: "Signed out — new login detected",
      desc:  "Your session ended because you signed in on another device.",
      icon:  <LogOut className="w-4 h-4 shrink-0" />,
      cls:   "bg-[#FEF3CD] border-[#F5CC6A] text-[#7A5800]",
    },
    expired: {
      title: "Session expired",
      desc:  "For your security, sessions time out after inactivity.",
      icon:  <Clock className="w-4 h-4 shrink-0" />,
      cls:   "bg-brand-soft border-brand-border text-brand",
    },
  };

  const alert = alerts[errorType] ?? {
    title: "Session ended",
    desc:  "Please sign in again to continue.",
    icon:  <Clock className="w-4 h-4 shrink-0" />,
    cls:   "bg-brand-soft border-brand-border text-brand",
  };

  return (
    <div className={`flex items-start gap-3 p-3.5 rounded-gs border text-[12.5px] mb-6 ${alert.cls}`}>
      {alert.icon}
      <div>
        <p className="font-semibold leading-tight">{alert.title}</p>
        <p className="opacity-80 mt-0.5 leading-snug">{alert.desc}</p>
      </div>
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function SignInPage() {
  const loginMutation = useSignin();
  const searchParams  = useSearchParams();
  const errorType     = searchParams.get("error");

  const form = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: "", password: "" },
  });

  return (
    <AuthShell
      heading={"Welcome back.\nSign in to your account."}
      subheading="Manage your policies, claims, and coverage — all in one place."
    >
      {/* Form heading */}
      <div className="mb-7">
        <h2 className="font-head text-[24px] font-extrabold tracking-[-0.025em] text-t1 mb-1">
          Sign in
        </h2>
        <p className="text-[13.5px] text-t3">
          Don't have an account?{" "}
          <Link href="/signup" className="font-semibold text-brand hover:text-brand-hover no-underline transition-colors">
            Create one free
          </Link>
        </p>
      </div>

      <SessionAlert errorType={errorType} />

      {/* Mutation error */}
      {loginMutation.isError && (
        <div className="mb-5 p-3.5 rounded-gs bg-red-50 border border-red-200 text-red-700 text-[12.5px] dark:bg-red-950/30 dark:border-red-800 dark:text-red-400">
          {(loginMutation.error as { message: string }).message || "Invalid credentials. Please try again."}
        </div>
      )}

      <Form {...form}>
        <form onSubmit={form.handleSubmit((d) => loginMutation.mutate(d))} className="space-y-4">

          {/* Email */}
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
                    disabled={loginMutation.isPending}
                    {...field}
                  />
                </div>
              </FormControl>
              <FormMessage className="text-[11.5px] text-red-500 mt-1" />
            </FormItem>
          )} />

          {/* Password */}
          <FormField control={form.control} name="password" render={({ field }) => (
            <FormItem>
              <div className="flex items-center justify-between mb-1.5">
                <label className={`${LABEL_CLS} mb-0`}>Password</label>
                <Link
                  href="/forgot-password"
                  className="text-[11.5px] font-semibold text-brand hover:text-brand-hover no-underline transition-colors"
                >
                  Forgot password?
                </Link>
              </div>
              <FormControl>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-t4 pointer-events-none" />
                  <input
                    type="password"
                    placeholder="••••••••"
                    className={FIELD_ICON_CLS}
                    disabled={loginMutation.isPending}
                    {...field}
                  />
                </div>
              </FormControl>
              <FormMessage className="text-[11.5px] text-red-500 mt-1" />
            </FormItem>
          )} />

          <button type="submit" className={BTN_CLS} disabled={loginMutation.isPending}>
            {loginMutation.isPending
              ? <><Loader2 className="w-4 h-4 animate-spin" /> Signing in…</>
              : "Sign in to my account"
            }
          </button>
        </form>
      </Form>

      <p className="mt-8 text-center text-[11.5px] text-t4">
        © {new Date().getFullYear()} Guardian Stack Insurance Group
      </p>
    </AuthShell>
  );
}