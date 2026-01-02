"use client";

import { useState, useMemo } from "react";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import Image from "next/image";
import { Eye, EyeOff, Check } from "lucide-react";
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
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { useSignup } from "../auth.react.query";
import { SignupFormData, signupSchema } from "../auth.schema";
import { isServerError } from "@/lib/api/error-handling";

const Requirement = ({ met, text }: { met: boolean; text: string }) => (
  <div className="flex items-center gap-2 transition-all duration-200">
    <div className={`flex h-4 w-4 items-center justify-center rounded-full border ${
      met ? "bg-emerald-500 border-emerald-500" : "bg-transparent border-slate-300 dark:border-slate-700"
    }`}>
      <Check className={`h-2.5 w-2.5 ${met ? "text-white" : "text-transparent"}`} strokeWidth={4} />
    </div>
    <span className={`text-[11px] font-medium ${
      met ? "text-slate-900 dark:text-slate-100" : "text-slate-400"
    }`}>
      {text}
    </span>
  </div>
);

export default function SignUpForm() {
  const [showPwd, setShowPwd] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const { mutateAsync: signup, isPending } = useSignup();

  const form = useForm<SignupFormData>({
    resolver: zodResolver(signupSchema),
    defaultValues: { username: "", email: "", password: "", confirmPassword: "" },
  });

  const password = useWatch({ control: form.control, name: "password" }) || "";
  const confirmPassword = useWatch({ control: form.control, name: "confirmPassword" }) || "";
  const username = useWatch({ control: form.control, name: "username" }) || "";

  const checks = useMemo(() => {
    const pwdLower = password.toLowerCase();
    const nameParts = username.toLowerCase().split(/\s+/).filter((p) => p.length > 2);
    return {
      length: password.length >= 8,
      upper: /[A-Z]/.test(password),
      number: /[0-9]/.test(password),
      special: /[^A-Za-z0-9]/.test(password),
      noName: username.length > 0 && !nameParts.some((part) => pwdLower.includes(part)),
      match: password.length > 0 && password === confirmPassword,
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
    <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-slate-950 p-4">
      <Card className="w-full max-w-md shadow-xl border-t-4 border-t-[#DAA520] bg-white dark:bg-slate-900 rounded-xl overflow-hidden">
        <CardHeader className="flex flex-col items-center space-y-3 pt-10 pb-4">
          
          {/* Raw / Glassmorphic Logo Style */}
          <div className="relative mb-2">
            {/* Subtle glow behind the logo */}
            <div className="absolute inset-0 bg-[#DAA520]/10 blur-2xl rounded-full" />
            
            <Image 
              src="/images/GS.png" 
              alt="Guardian Stack Logo" 
              width={80} 
              height={80} 
              className="relative object-contain drop-shadow-sm transition-transform duration-500 hover:scale-105"
              priority
            />
          </div>

          <div className="text-center relative">
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
              Create your <span className="text-[#DAA520]">Account</span>
            </h1>
            <p className="text-xs font-medium text-slate-500 mt-1">
              Join the Guardian Stack protection network
            </p>
          </div>
        </CardHeader>

        <CardContent className="space-y-6 pb-8">
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <div className="space-y-3">
                <FormField
                  control={form.control}
                  name="username"
                  render={({ field }) => (
                    <FormItem className="space-y-1">
                      <FormLabel className="text-xs font-semibold text-slate-700 dark:text-slate-300">Full Name</FormLabel>
                      <FormControl>
                        <Input 
                          placeholder="John Doe" 
                          {...field} 
                          className="h-10 text-sm border-slate-200 dark:border-slate-800 focus:border-[#DAA520] focus:ring-1 focus:ring-[#DAA520]/20 rounded-lg" 
                        />
                      </FormControl>
                      <FormMessage className="text-xs text-red-500" />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="email"
                  render={({ field }) => (
                    <FormItem className="space-y-1">
                      <FormLabel className="text-xs font-semibold text-slate-700 dark:text-slate-300">Email Address</FormLabel>
                      <FormControl>
                        <Input 
                          type="email" 
                          placeholder="john@company.com" 
                          {...field} 
                          className="h-10 text-sm border-slate-200 dark:border-slate-800 focus:border-[#DAA520] focus:ring-1 focus:ring-[#DAA520]/20 rounded-lg" 
                        />
                      </FormControl>
                      <FormMessage className="text-xs text-red-500" />
                    </FormItem>
                  )}
                />

                <div className="space-y-4 p-4 bg-slate-50/50 dark:bg-slate-800/20 backdrop-blur-sm rounded-xl border border-slate-100 dark:border-slate-800">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <FormField
                      control={form.control}
                      name="password"
                      render={({ field }) => (
                        <FormItem className="space-y-1">
                          <FormLabel className="text-[11px] font-semibold text-slate-600">Password</FormLabel>
                          <FormControl>
                            <div className="relative">
                              <Input 
                                type={showPwd ? "text" : "password"} 
                                placeholder="••••••••"
                                {...field} 
                                className="h-9 text-sm border-slate-200 focus:border-[#DAA520] pr-8 rounded-md bg-white/80 dark:bg-slate-900/80" 
                              />
                              <button type="button" onClick={() => setShowPwd(!showPwd)} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400">
                                {showPwd ? <EyeOff size={14} /> : <Eye size={14} />}
                              </button>
                            </div>
                          </FormControl>
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="confirmPassword"
                      render={({ field }) => (
                        <FormItem className="space-y-1">
                          <FormLabel className="text-[11px] font-semibold text-slate-600">Confirm</FormLabel>
                          <FormControl>
                            <div className="relative">
                              <Input 
                                type={showConfirm ? "text" : "password"} 
                                placeholder="••••••••"
                                {...field} 
                                className="h-9 text-sm border-slate-200 focus:border-[#DAA520] pr-8 rounded-md bg-white/80 dark:bg-slate-900/80" 
                              />
                              <button type="button" onClick={() => setShowConfirm(!showConfirm)} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400">
                                {showConfirm ? <EyeOff size={14} /> : <Eye size={14} />}
                              </button>
                            </div>
                          </FormControl>
                        </FormItem>
                      )}
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-y-2 pt-1">
                    <Requirement met={checks.length} text="8+ Characters" />
                    <Requirement met={checks.upper} text="1 Uppercase" />
                    <Requirement met={checks.number} text="1 Number" />
                    <Requirement met={checks.special} text="1 Symbol" />
                    <Requirement met={checks.noName} text="Secure" />
                    <Requirement met={checks.match} text="Matches" />
                  </div>
                </div>
              </div>

              <Button
                type="submit"
                disabled={!allMet || isPending}
                className={`w-full h-11 text-sm font-bold shadow-md transition-all rounded-lg ${
                  allMet 
                    ? "bg-slate-900 text-white hover:bg-slate-800 dark:bg-[#DAA520] dark:text-slate-950" 
                    : "bg-slate-100 text-slate-400 cursor-not-allowed border-none shadow-none"
                }`}
              >
                {isPending ? "Creating Account..." : "Create Secure Account"}
              </Button>
            </form>
          </Form>

          <div className="text-center">
            <p className="text-xs font-medium text-slate-500">
              Already have an account? <Link href="/login" className="text-[#DAA520] font-bold hover:underline underline-offset-4">Log in here</Link>
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}