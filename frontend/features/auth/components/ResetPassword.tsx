"use client";

import { useSearchParams } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { Lock, Loader2, ArrowLeft } from "lucide-react";
import Link from "next/link";
import Image from "next/image";

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
  CardHeader,
  CardFooter,
} from "@/components/ui/card";
import { useResetPassword } from "../auth.react.query";

const resetSchema = z.object({
  email: z.string().email("Invalid email address."),
  otp: z
    .string()
    .length(6, { message: "Code must be exactly 6 digits." }),
  newPassword: z.string().min(8, "Password must be at least 8 characters."),
});

export default function ResetPassword() {
  const searchParams = useSearchParams();
  const emailFromQuery = searchParams.get("email") || "";

  const { mutate: resetPassword, isPending } = useResetPassword();

  const form = useForm<z.infer<typeof resetSchema>>({
    resolver: zodResolver(resetSchema),
    defaultValues: {
      email: emailFromQuery,
      otp: "",
      newPassword: "",
    },
  });

  function onSubmit(values: z.infer<typeof resetSchema>) {
    resetPassword(values);
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-slate-950 p-4">
      <Card className="w-full max-w-md shadow-xl border-t-4 border-t-[#DAA520] bg-white dark:bg-slate-900 rounded-xl overflow-hidden border-x-slate-200 border-b-slate-200 dark:border-slate-800">
        <CardHeader className="flex flex-col items-center space-y-3 pt-10 pb-6">
          
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
              Secure your <span className="text-[#DAA520]">Account</span>
            </h1>
            <p className="text-xs font-medium text-slate-500 mt-1">
              Set your new password to restore access
            </p>
          </div>
        </CardHeader>

        <CardContent className="pb-8 px-8">
          <div className="mb-6 p-4 bg-slate-50/50 dark:bg-slate-800/20 backdrop-blur-sm rounded-xl text-center border border-slate-100 dark:border-slate-800">
            <p className="text-xs text-slate-600 dark:text-slate-400">
              Enter the 6-digit code sent to:
            </p>
            <p className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-1 break-all">
              {emailFromQuery || "your email address"}
            </p>
          </div>

          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              {/* OTP Field */}
              <FormField
                control={form.control}
                name="otp"
                render={({ field }) => (
                  <FormItem className="flex flex-col items-center justify-center space-y-4">
                    <FormLabel className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                      Verification Code
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

              {/* Password Field */}
              <FormField
                control={form.control}
                name="newPassword"
                render={({ field }) => (
                  <FormItem className="space-y-2">
                    <FormLabel className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                      New Password
                    </FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                        <Input
                          type="password"
                          placeholder="••••••••"
                          className="pl-10 h-11 text-sm border-slate-200 dark:border-slate-800 focus:border-[#DAA520] focus:ring-1 focus:ring-[#DAA520]/20 rounded-lg bg-white dark:bg-slate-900"
                          {...field}
                        />
                      </div>
                    </FormControl>
                    <FormMessage className="text-xs font-medium text-red-500" />
                  </FormItem>
                )}
              />

              <Button 
                type="submit" 
                className="w-full h-12 mt-2 text-sm font-bold shadow-md transition-all rounded-lg text-white bg-slate-900 hover:bg-slate-800 dark:bg-[#DAA520] dark:text-slate-950" 
                disabled={isPending}
              >
                {isPending ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Updating...
                  </>
                ) : (
                  "Update Password"
                )}
              </Button>
            </form>
          </Form>
        </CardContent>

        <CardFooter className="flex justify-center border-t border-slate-100 dark:border-slate-800 py-6">
          <Link 
            href="/login" 
            className="group flex items-center gap-2 text-xs font-bold text-slate-500 hover:text-slate-900 dark:hover:text-slate-200 transition-colors"
          >
            <ArrowLeft className="h-3.5 w-3.5 transition-transform group-hover:-translate-x-1" />
            Return to sign in
          </Link>
        </CardFooter>
      </Card>
    </div>
  );
}