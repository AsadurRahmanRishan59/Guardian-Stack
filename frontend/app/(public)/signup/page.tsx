"use client";

// app/(public)/signup/page.tsx

import { useState, useMemo } from "react";
import Link from "next/link";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Eye, EyeOff, Check, Loader2 } from "lucide-react";

import { Form, FormControl, FormField, FormItem, FormMessage } from "@/components/ui/form";
import { useSignup } from "@/features/auth/auth.react.query";
import { SignupFormData, signupSchema } from "@/features/auth/auth.schema";
import { isServerError } from "@/lib/api/error-handling";
import { AuthShell, FIELD_CLS, LABEL_CLS, BTN_CLS } from "@/components/auth/AuthShell";

// ─── Password requirement pill ────────────────────────────────────────────────

function Req({ met, text }: { met: boolean; text: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className={`
        w-4 h-4 rounded-full flex items-center justify-center shrink-0
        transition-all duration-200
        ${met ? "bg-gs-green" : "border border-gs-line bg-surface-2"}
      `}>
        <Check className={`w-2.5 h-2.5 stroke-[3] ${met ? "text-white" : "text-transparent"}`} />
      </div>
      <span className={`text-[12px] font-medium transition-colors duration-150 ${met ? "text-t1" : "text-t4"}`}>
        {text}
      </span>
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function SignUpPage() {
  const [showPwd,     setShowPwd]     = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const { mutateAsync: signup, isPending } = useSignup();

  const form = useForm<SignupFormData>({
    resolver: zodResolver(signupSchema),
    defaultValues: { username: "", email: "", password: "", confirmPassword: "" },
  });

  const password        = useWatch({ control: form.control, name: "password" })        || "";
  const confirmPassword = useWatch({ control: form.control, name: "confirmPassword" }) || "";
  const username        = useWatch({ control: form.control, name: "username" })        || "";

  const checks = useMemo(() => {
    const lower     = password.toLowerCase();
    const nameParts = username.toLowerCase().split(/\s+/).filter((p) => p.length > 2);
    return {
      length:  password.length >= 8,
      upper:   /[A-Z]/.test(password),
      number:  /[0-9]/.test(password),
      special: /[^A-Za-z0-9]/.test(password),
      noName:  username.length > 0 && !nameParts.some((p) => lower.includes(p)),
      match:   password.length > 0 && password === confirmPassword,
    };
  }, [password, confirmPassword, username]);

  const allMet = Object.values(checks).every(Boolean);

  const onSubmit = async (values: SignupFormData) => {
    try {
      await signup({ username: values.username, email: values.email, password: values.password });
      form.reset();
    } catch (error) {
      if (isServerError(error)) {
        const dataObj = error.data as Record<string, string>;
        Object.entries(dataObj || {}).forEach(([field, message]) => {
          form.setError(field as keyof SignupFormData, { type: "server", message });
        });
      }
    }
  };

  return (
    <AuthShell
      heading={"Get covered in\nunder 2 minutes."}
      subheading="Create your free account and get your first policy issued instantly — no paperwork, no waiting."
    >
      <div className="mb-7">
        <h2 className="font-head text-[24px] font-extrabold tracking-[-0.025em] text-t1 mb-1">
          Create account
        </h2>
        <p className="text-[13.5px] text-t3">
          Already have one?{" "}
          <Link href="/signin" className="font-semibold text-brand hover:text-brand-hover no-underline transition-colors">
            Sign in
          </Link>
        </p>
      </div>

      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">

          {/* Name */}
          <FormField control={form.control} name="username" render={({ field }) => (
            <FormItem>
              <label className={LABEL_CLS}>Full name</label>
              <FormControl>
                <input type="text" placeholder="John Doe" className={FIELD_CLS} {...field} />
              </FormControl>
              <FormMessage className="text-[11.5px] text-red-500 mt-1" />
            </FormItem>
          )} />

          {/* Email */}
          <FormField control={form.control} name="email" render={({ field }) => (
            <FormItem>
              <label className={LABEL_CLS}>Email address</label>
              <FormControl>
                <input type="email" placeholder="you@example.com" className={FIELD_CLS} {...field} />
              </FormControl>
              <FormMessage className="text-[11.5px] text-red-500 mt-1" />
            </FormItem>
          )} />

          {/* Password block */}
          <div className="rounded-gs border border-gs-line/60 bg-surface-2 p-4 space-y-3">
            <div className="grid grid-cols-2 gap-3">
              {/* Password */}
              <FormField control={form.control} name="password" render={({ field }) => (
                <FormItem>
                  <label className={LABEL_CLS}>Password</label>
                  <FormControl>
                    <div className="relative">
                      <input
                        type={showPwd ? "text" : "password"}
                        placeholder="••••••••"
                        className={`${FIELD_CLS} pr-10`}
                        {...field}
                      />
                      <button
                        type="button"
                        onClick={() => setShowPwd(!showPwd)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-t4 hover:text-t2 transition-colors bg-transparent border-none p-0 cursor-pointer"
                      >
                        {showPwd ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </FormControl>
                </FormItem>
              )} />

              {/* Confirm */}
              <FormField control={form.control} name="confirmPassword" render={({ field }) => (
                <FormItem>
                  <label className={LABEL_CLS}>Confirm</label>
                  <FormControl>
                    <div className="relative">
                      <input
                        type={showConfirm ? "text" : "password"}
                        placeholder="••••••••"
                        className={`${FIELD_CLS} pr-10`}
                        {...field}
                      />
                      <button
                        type="button"
                        onClick={() => setShowConfirm(!showConfirm)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-t4 hover:text-t2 transition-colors bg-transparent border-none p-0 cursor-pointer"
                      >
                        {showConfirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </FormControl>
                </FormItem>
              )} />
            </div>

            {/* Requirements grid */}
            <div className="grid grid-cols-2 gap-x-4 gap-y-2 pt-1">
              <Req met={checks.length}  text="8+ characters" />
              <Req met={checks.upper}   text="Uppercase letter" />
              <Req met={checks.number}  text="Number" />
              <Req met={checks.special} text="Symbol" />
              <Req met={checks.noName}  text="Doesn't contain name" />
              <Req met={checks.match}   text="Passwords match" />
            </div>
          </div>

          <button
            type="submit"
            className={BTN_CLS}
            disabled={!allMet || isPending}
          >
            {isPending
              ? <><Loader2 className="w-4 h-4 animate-spin" /> Creating account…</>
              : "Create secure account"
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