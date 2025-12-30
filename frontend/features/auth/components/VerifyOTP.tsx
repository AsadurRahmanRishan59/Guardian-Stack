"use client";

import { useSearchParams, useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useState, useEffect } from "react";
import { ShieldCheck, ArrowLeft, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Form, FormControl, FormField, FormItem, FormMessage } from "@/components/ui/form";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp"; // Shadcn component
import { useVerifyOtp, useResendOtp } from "../auth.react.query";
import { verifyOtpSchema, VerifyOtpData } from "../auth.schema";

import Link from "next/link";
import { isServerError } from "@/lib/api/error-handling";

export default function VerifyOtp() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const email = searchParams.get("email") || "";
  
  const { mutateAsync: verify, isPending } = useVerifyOtp();
  const { mutate: resend, isPending: isResending } = useResendOtp();
  
  const [timer, setTimer] = useState(60);

  useEffect(() => {
    const interval = setInterval(() => {
      setTimer((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(interval);
  }, []);

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
          message: typeof error.message === 'string' ? error.message : "Invalid or expired code" 
        });
      }
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50 p-4 dark:bg-slate-950">
      <Card className="w-full max-w-md shadow-xl border-gray-200 dark:border-slate-800 dark:bg-slate-900">
        <CardHeader className="text-center space-y-2">
          <div className="flex justify-center">
            <div className="p-3 bg-blue-50 dark:bg-blue-900/20 rounded-full text-blue-600">
              <ShieldCheck size={32} />
            </div>
          </div>
          <CardTitle className="text-2xl font-bold">Two-Step Verification</CardTitle>
          <CardDescription>
            We&apos;ve sent a 6-digit code to <br />
            <span className="font-medium text-slate-900 dark:text-slate-200">{email}</span>
          </CardDescription>
        </CardHeader>

        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              <FormField
                control={form.control}
                name="otp"
                render={({ field }) => (
                  <FormItem className="flex flex-col items-center justify-center">
                    <FormControl>
                      {/* Using Shadcn InputOTP for that professional split-box look */}
                      <InputOTP maxLength={6} {...field}>
                        <InputOTPGroup className="gap-2">
                          <InputOTPSlot className="w-12 h-14 text-lg border-2" index={0} />
                          <InputOTPSlot className="w-12 h-14 text-lg border-2" index={1} />
                          <InputOTPSlot className="w-12 h-14 text-lg border-2" index={2} />
                          <InputOTPSlot className="w-12 h-14 text-lg border-2" index={3} />
                          <InputOTPSlot className="w-12 h-14 text-lg border-2" index={4} />
                          <InputOTPSlot className="w-12 h-14 text-lg border-2" index={5} />
                        </InputOTPGroup>
                      </InputOTP>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <Button type="submit" disabled={isPending} className="w-full bg-blue-600 hover:bg-blue-700 h-11">
                {isPending ? "Verifying..." : "Verify Account"}
              </Button>

              <div className="text-center space-y-4">
                <p className="text-sm text-slate-500">
                  Didn&apos;t receive the code?{" "}
                  {timer > 0 ? (
                    <span className="text-blue-600 font-medium">Wait {timer}s</span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => { resend({ email }); setTimer(60); }}
                      disabled={isResending}
                      className="text-blue-600 hover:underline font-medium inline-flex items-center gap-1"
                    >
                      {isResending && <RefreshCw size={14} className="animate-spin" />}
                      Resend Code
                    </button>
                  )}
                </p>

                <Link href="/signup" className="inline-flex items-center gap-2 text-sm text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 transition-colors">
                  <ArrowLeft size={14} />
                  Back to Sign Up
                </Link>
              </div>
            </form>
          </Form>
        </CardContent>
      </Card>
    </div>
  );
}