"use client";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { Mail, ArrowLeft, Loader2 } from "lucide-react";
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
  Card,
  CardContent,
  CardFooter,
  CardHeader,
} from "@/components/ui/card";
import { useForgotPassword } from "../auth.react.query";

const formSchema = z.object({
  email: z.string().email("Please enter a valid email address."),
});

export default function ForgotPassword() {
  const { mutate: forgotPassword, isPending } = useForgotPassword();

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      email: "",
    },
  });

  function onSubmit(values: z.infer<typeof formSchema>) {
    forgotPassword({ email: values.email });
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
              Reset your <span className="text-[#DAA520]">Password</span>
            </h1>
            <p className="text-xs font-medium text-slate-500 mt-1">
              We&apos;ll help you get back into your account
            </p>
          </div>
        </CardHeader>

        <CardContent className="pb-8 px-8">
          <div className="mb-6 p-4 bg-slate-50/50 dark:bg-slate-800/20 backdrop-blur-sm rounded-xl border border-slate-100 dark:border-slate-800">
            <p className="text-xs leading-relaxed text-slate-600 dark:text-slate-400 text-center">
              Please enter the email address associated with your policy. We will send you a 6-digit code to reset your password.
            </p>
          </div>

          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-5">
              <FormField
                control={form.control}
                name="email"
                render={({ field }) => (
                  <FormItem className="space-y-2">
                    <FormLabel className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                      Email Address
                    </FormLabel>
                    <FormControl>
                      <div className="relative">
                        <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                        <Input
                          placeholder="john@example.com"
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
                    Sending Code...
                  </>
                ) : (
                  "Send Reset Link"
                )}
              </Button>
            </form>
          </Form>
        </CardContent>

        <CardFooter className="flex justify-center border-t border-slate-100 dark:border-slate-800 py-6">
          <Link
            href="/signin"
            className="group flex items-center text-xs font-bold text-slate-500 hover:text-slate-900 dark:hover:text-slate-200 transition-colors"
          >
            <ArrowLeft className="mr-2 h-3.5 w-3.5 transition-transform group-hover:-translate-x-1" />
            Return to sign in
          </Link>
        </CardFooter>
      </Card>
    </div>
  );
}