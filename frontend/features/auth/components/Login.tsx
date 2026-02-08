"use client";

import Link from "next/link";
import Image from "next/image";
import { useSignin } from "../auth.react.query";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";

import {
  Card,
  CardHeader,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Clock, Loader2, Lock, LogOut, Mail } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";

import { loginSchema, LoginFormData } from "../auth.schema";
import { useSearchParams } from "next/navigation";

export default function Login() {
  const loginMutation = useSignin();
  const searchParams = useSearchParams();

  const errorType = searchParams.get("error");

  const getNiceMessage = () => {
    switch (errorType) {
      case "displaced":
        return {
          title: "New Login Detected",
          desc: "You were signed out because you logged in on another device.",
          icon: <LogOut className="h-4 w-4" />,
          color: "border-amber-200 bg-amber-50 text-amber-900",
        };
      case "expired":
        return {
          title: "Session Expired",
          desc: "For your security, sessions time out after a period of inactivity.",
          icon: <Clock className="h-4 w-4" />,
          color: "border-blue-200 bg-blue-50 text-blue-900",
        };
      case null:
        return null; // No error, no alert
      default:
        return {
          title: "Session Expired",
          desc: "Please Login Again",
          icon: <Clock className="h-4 w-4" />,
          color: "border-blue-200 bg-blue-50 text-blue-900",
        };
    }
  };

  const alertData = getNiceMessage();

  const form = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      email: "",
      password: "",
    },
  });

  const onSubmit = (data: LoginFormData) => {
    loginMutation.mutate(data);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-slate-950 p-4">
      <Card className="w-full max-w-md shadow-xl border-t-4 border-t-[#DAA520] bg-white dark:bg-slate-900 rounded-xl overflow-hidden border-x-slate-200 border-b-slate-200 dark:border-slate-800">
        <CardHeader className="space-y-3 flex flex-col items-center pt-10 pb-6">
          {/* Branded Glassmorphic Logo Container */}
          <div className="relative mb-2 flex items-center justify-center">
            {/* Soft gold aura/glow behind the transparent logo */}
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
              Welcome to <span className="text-[#DAA520]">Guardian Stack</span>
            </h1>
            <p className="text-xs font-medium text-slate-500 mt-1">
              Sign in to manage your protection
            </p>
          </div>
        </CardHeader>

        <CardContent className="pb-8 px-8">
          {alertData && (
            <div
              role="alert"
              className={`mb-6 rounded-lg p-4 border ${alertData.color}`}
            >
              <div className="flex items-start gap-3">
                <div className="shrink-0 mt-0.5">{alertData.icon}</div>
                <div className="flex-1 min-w-0">
                  <p className="font-bold text-[13px] leading-tight mb-1">
                    {alertData.title}
                  </p>
                  <p className="text-[11px] font-medium opacity-90 leading-relaxed">
                    {alertData.desc}
                  </p>
                </div>
              </div>
            </div>
          )}
          {loginMutation.isError && (
            <Alert
              variant="destructive"
              className="mb-6 border-red-100 bg-red-50 text-red-900 dark:bg-red-900/20 dark:text-red-400 rounded-lg"
            >
              <AlertDescription className="text-xs font-semibold">
                {(loginMutation.error as { message: string }).message ||
                  "Please check your credentials and try again."}
              </AlertDescription>
            </Alert>
          )}
          <form onSubmit={form.handleSubmit(onSubmit)} className="grid gap-5">
            {/* Email Field */}
            <div className="grid gap-2">
              <Label
                htmlFor="email"
                className="text-xs font-semibold text-slate-700 dark:text-slate-300"
              >
                Email Address
              </Label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                <Input
                  id="email"
                  {...form.register("email")}
                  placeholder="john@example.com"
                  disabled={loginMutation.isPending}
                  className="pl-10 h-11 text-sm border-slate-200 dark:border-slate-800 focus:border-[#DAA520] focus:ring-1 focus:ring-[#DAA520]/20 rounded-lg bg-white dark:bg-slate-900"
                />
              </div>
              {form.formState.errors.email && (
                <p className="text-xs font-medium text-red-500">
                  {form.formState.errors.email.message}
                </p>
              )}
            </div>

            {/* Password Field */}
            <div className="grid gap-2">
              <div className="flex items-center justify-between">
                <Label
                  htmlFor="password"
                  className="text-xs font-semibold text-slate-700 dark:text-slate-300"
                >
                  Password
                </Label>
                <Link
                  href="/forgot-password"
                  className="text-xs font-bold text-[#DAA520] hover:text-[#B8860B] transition-colors"
                >
                  Forgot password?
                </Link>
              </div>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                <Input
                  id="password"
                  type="password"
                  {...form.register("password")}
                  placeholder="••••••••"
                  disabled={loginMutation.isPending}
                  className="pl-10 h-11 text-sm border-slate-200 dark:border-slate-800 focus:border-[#DAA520] focus:ring-1 focus:ring-[#DAA520]/20 rounded-lg bg-white dark:bg-slate-900"
                />
              </div>
              {form.formState.errors.password && (
                <p className="text-xs font-medium text-red-500">
                  {form.formState.errors.password.message}
                </p>
              )}
            </div>

            <Button
              type="submit"
              className={`w-full h-12 mt-2 text-sm font-bold shadow-md transition-all rounded-lg text-white
                ${
                  loginMutation.isPending
                    ? "bg-slate-400"
                    : "bg-slate-900 hover:bg-slate-800 dark:bg-[#DAA520] dark:text-slate-950"
                }`}
              disabled={loginMutation.isPending}
            >
              {loginMutation.isPending ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Signing in...
                </>
              ) : (
                "Sign In to My Account"
              )}
            </Button>
          </form>
          <div className="mt-8 text-center">
            <p className="text-xs font-medium text-slate-500">
              New to Guardian Stack?{" "}
              <Link
                href="/signup"
                className="text-[#DAA520] font-bold hover:underline underline-offset-4"
              >
                Get started
              </Link>
            </p>
          </div>
        </CardContent>

        <CardFooter className="flex justify-center text-[11px] text-slate-400 font-medium pb-8">
          © {new Date().getFullYear()} Guardian Stack Insurance Group
        </CardFooter>
      </Card>
    </div>
  );
}
