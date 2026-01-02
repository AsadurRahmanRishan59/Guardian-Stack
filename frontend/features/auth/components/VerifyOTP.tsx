"use client";

import { useSearchParams, useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useState, useEffect } from "react";
import Image from "next/image";
import { ArrowLeft, RefreshCw, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardFooter } from "@/components/ui/card";
import { Form, FormControl, FormField, FormItem, FormMessage, FormLabel } from "@/components/ui/form";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
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
          message: typeof error.message === 'string' ? error.message : "The code entered is incorrect" 
        });
      }
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50 p-4 dark:bg-slate-950">
      <Card className="w-full max-w-md shadow-xl border-t-4 border-t-[#DAA520] bg-white dark:bg-slate-900 rounded-xl overflow-hidden border-x-slate-200 border-b-slate-200 dark:border-slate-800">
        <CardHeader className="space-y-3 flex flex-col items-center pt-10 pb-4">
          
          {/* Branded Glassmorphic Logo Treatment */}
          <div className="relative mb-2 flex items-center justify-center">
            {/* Soft gold aura/glow */}
            <div className="absolute h-16 w-16 bg-[#DAA520]/15 blur-2xl rounded-full" />
            
            <Image 
              src="/images/GS.png" 
              alt="Guardian Stack Logo" 
              width={80} 
              height={80} 
              className="relative object-contain transition-transform duration-500 hover:scale-105"
              priority
            />
          </div>

          <div className="text-center relative">
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
              Verify your <span className="text-[#DAA520]">Account</span>
            </h1>
            <p className="text-xs font-medium text-slate-500 mt-1">
              Final step to secure your protection
            </p>
          </div>
        </CardHeader>

        <CardContent className="pb-8 px-8">
          <div className="mb-6 p-4 bg-slate-50/50 dark:bg-slate-800/20 backdrop-blur-sm rounded-xl text-center border border-slate-100 dark:border-slate-800">
            <p className="text-xs text-slate-600 dark:text-slate-400">
              We&apos;ve sent a 6-digit verification code to:
            </p>
            <p className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-1 break-all">
              {email || "your email address"}
            </p>
          </div>

          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              <FormField
                control={form.control}
                name="otp"
                render={({ field }) => (
                  <FormItem className="flex flex-col items-center justify-center space-y-4">
                    <FormLabel className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                      Enter Verification Code
                    </FormLabel>
                    <FormControl>
                      <InputOTP maxLength={6} {...field}>
                        <InputOTPGroup className="gap-2">
                          {[...Array(6)].map((_, i) => (
                            <InputOTPSlot
                              key={i}
                              index={i}
                              className="h-12 w-11 text-lg font-semibold border-slate-200 dark:border-slate-800 rounded-lg focus:border-[#DAA520] focus:ring-1 focus:ring-[#DAA520]/20 transition-all bg-white dark:bg-slate-950"
                            />
                          ))}
                        </InputOTPGroup>
                      </InputOTP>
                    </FormControl>
                    <FormMessage className="text-xs font-medium text-red-500" />
                  </FormItem>
                )}
              />

              <div className="space-y-4 pt-2">
                <Button 
                  type="submit" 
                  disabled={isPending} 
                  className="w-full h-12 text-sm font-bold shadow-md transition-all rounded-lg text-white bg-slate-900 hover:bg-slate-800 dark:bg-[#DAA520] dark:text-slate-950"
                >
                  {isPending ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Verifying...
                    </>
                  ) : (
                    "Complete Registration"
                  )}
                </Button>

                <div className="text-center">
                  <p className="text-xs text-slate-500">
                    Didn&apos;t get the code?{" "}
                    {timer > 0 ? (
                      <span className="text-slate-400 font-medium italic">Retry in {timer}s</span>
                    ) : (
                      <button
                        type="button"
                        onClick={() => { resend({ email }); setTimer(60); }}
                        disabled={isResending}
                        className="text-[#DAA520] hover:text-[#B8860B] font-bold inline-flex items-center gap-1 transition-colors underline-offset-4 hover:underline"
                      >
                        {isResending && <RefreshCw size={12} className="animate-spin" />}
                        Send new code
                      </button>
                    )}
                  </p>
                </div>
              </div>
            </form>
          </Form>
        </CardContent>

        <CardFooter className="flex justify-center border-t border-slate-100 dark:border-slate-800 py-6">
          <Link 
            href="/signup" 
            className="group flex items-center gap-2 text-xs font-bold text-slate-500 hover:text-slate-900 dark:hover:text-slate-200 transition-colors"
          >
            <ArrowLeft className="h-3.5 w-3.5 transition-transform group-hover:-translate-x-1" />
            Back to Sign Up
          </Link>
        </CardFooter>
      </Card>
    </div>
  );
}