"use client";

// app/unauthorized/page.tsx

import Link from "next/link";
import Image from "next/image";
import { ShieldOff, ArrowLeft } from "lucide-react";
import { ThemeToggle } from "@/components/theme-toggle";

export default function UnauthorizedPage() {
  return (
    <div className="min-h-screen flex flex-col bg-surface font-body">

      {/* Top bar */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-gs-line/50 bg-surface-card shrink-0">
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-[12.5px] font-medium text-t3 hover:text-brand no-underline transition-colors duration-150"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Back to Guardian Stack
        </Link>
        <ThemeToggle />
      </div>

      {/* Body */}
      <div className="flex-1 flex items-center justify-center px-5 py-16">
        <div className="w-full max-w-[400px] text-center animate-fade-up">

          {/* Logo */}
          <Link href="/" className="inline-flex items-center gap-2.5 no-underline mb-10 justify-center">
            <Image
              src="/images/GS.png"
              alt="Guardian Stack"
              width={34} height={34}
              className="rounded-[8px] object-contain"
              priority
            />
            <span className="font-head text-[15px] font-bold tracking-tight text-t1">
              Guardian Stack
            </span>
          </Link>

          {/* Icon */}
          <div className="w-16 h-16 rounded-[16px] bg-red-50 border border-red-100 dark:bg-red-950/30 dark:border-red-900/50 flex items-center justify-center mx-auto mb-6">
            <ShieldOff className="w-8 h-8 text-red-500 dark:text-red-400" />
          </div>

          {/* Text */}
          <h1 className="font-head text-[28px] font-extrabold tracking-[-0.025em] text-t1 mb-3">
            Access denied
          </h1>
          <p className="text-[14px] leading-[1.7] text-t3 mb-8 max-w-[320px] mx-auto">
            You don't have permission to view this page. Contact your administrator if you believe this is a mistake.
          </p>

          {/* Actions */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
            <Link
              href="/dashboard"
              className="
                inline-flex items-center justify-center
                h-10 px-6 rounded-gs
                bg-brand hover:bg-brand-hover
                text-white text-[13.5px] font-semibold no-underline
                transition-all duration-150 hover:-translate-y-px
                hover:shadow-[0_6px_20px_rgba(232,92,13,0.25)]
              "
            >
              Go to dashboard
            </Link>
            <Link
              href="/"
              className="
                inline-flex items-center justify-center
                h-10 px-6 rounded-gs
                bg-surface-card border border-gs-line
                text-[13.5px] font-medium text-t2 no-underline
                hover:border-brand hover:text-brand
                transition-all duration-150
              "
            >
              Return home
            </Link>
          </div>

          <p className="mt-12 text-[11.5px] text-t4">
            © {new Date().getFullYear()} Guardian Stack Insurance Group
          </p>
        </div>
      </div>
    </div>
  );
}