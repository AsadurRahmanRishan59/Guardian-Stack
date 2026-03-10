/**
 * AUTH PAGES — Guardian Stack design system
 *
 * Shared layout:
 *   · bg-surface (warm off-white / near-black in dark)
 *   · Split: left brand panel (hidden on mobile) + right form panel
 *   · font-head (Sora) for headings, font-body (Plus Jakarta Sans) for everything else
 *   · Brand orange (#E85C0D light / #FF7432 dark) — NO more #DAA520 gold
 *   · rounded-gs (10px), rounded-gs-sm (6px)
 *   · text-t1/t2/t3/t4, bg-surface-card, border-gs-line
 *
 * Files to create:
 *   app/(public)/signin/page.tsx         → SignInPage
 *   app/(public)/signup/page.tsx         → SignUpPage
 *   app/(public)/forgot-password/page.tsx → ForgotPasswordPage
 *   app/(public)/reset-password/page.tsx  → ResetPasswordPage
 *   app/(public)/verify-otp/page.tsx      → VerifyOtpPage
 *
 * Each page is self-contained below — split at the "// ─── FILE:" markers.
 */

// ─── FILE: components/auth/AuthShell.tsx ──────────────────────────────────────
// Shared two-column wrapper used by every auth page.
// Left: warm brand panel with logo + tagline (hidden on mobile)
// Right: form content
// Top bar: landing page link (left) + theme toggle (right)

"use client";

import Image from "next/image";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { ThemeToggle } from "@/components/theme-toggle";

export function AuthShell({
  children,
  heading,
  subheading,
}: {
  children: React.ReactNode;
  heading: string;
  subheading: string;
}) {
  return (
    <div className="min-h-screen flex flex-col bg-surface font-body">

      {/* ── Top bar ──────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-gs-line/50 bg-surface-card shrink-0">
        <Link
          href="/"
          className="
            inline-flex items-center gap-1.5
            text-[12.5px] font-medium text-t3
            hover:text-brand no-underline
            transition-colors duration-150
          "
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Back to Guardian Stack
        </Link>
        <ThemeToggle />
      </div>

      {/* ── Body ─────────────────────────────────────────────────────────────── */}
      <div className="flex flex-1 min-h-0">

        {/* Left brand panel — hidden on mobile */}
        <div className="
          hidden lg:flex flex-col justify-between
          w-[420px] shrink-0
          bg-surface-card border-r border-gs-line/50
          px-10 py-14
        ">
          {/* Logo */}
          <div>
            <Link href="/" className="inline-flex items-center gap-3 no-underline mb-14">
              <Image
                src="/images/GS.png"
                alt="Guardian Stack"
                width={38} height={38}
                className="rounded-[10px] object-contain shrink-0"
                priority
              />
              <span className="font-head text-[15px] font-bold tracking-tight text-t1">
                Guardian Stack
              </span>
            </Link>

            {/* Heading */}
            <h1 className="font-head text-[clamp(26px,2.6vw,34px)] font-extrabold tracking-[-0.03em] leading-[1.15] text-t1 mb-4">
              {heading}
            </h1>
            <p className="text-[14px] leading-[1.7] text-t3 max-w-[300px]">
              {subheading}
            </p>
          </div>

          {/* Bottom trust row */}
          <div className="space-y-3">
            {[
              { dot: "bg-gs-green",   text: "IDRA Licensed & Regulated" },
              { dot: "bg-brand",      text: "SSLCommerz Secured Payments" },
              { dot: "bg-gs-green",   text: "ISO 27001 Certified Platform" },
            ].map((item) => (
              <div key={item.text} className="flex items-center gap-2.5">
                <span className={`w-2 h-2 rounded-full shrink-0 ${item.dot}`} />
                <span className="text-[12.5px] font-medium text-t3">{item.text}</span>
              </div>
            ))}
            <p className="text-[11.5px] text-t4 pt-2">
              © {new Date().getFullYear()} Guardian Stack Insurance Group
            </p>
          </div>
        </div>

        {/* Right form panel */}
        <div className="flex-1 flex items-center justify-center px-5 py-10 overflow-y-auto">
          <div className="w-full max-w-[420px] animate-fade-up">

            {/* Mobile-only logo */}
            <div className="flex lg:hidden justify-center mb-8">
              <Link href="/" className="inline-flex items-center gap-2.5 no-underline">
                <Image
                  src="/images/GS.png"
                  alt="Guardian Stack"
                  width={34} height={34}
                  className="rounded-[8px] object-contain"
                />
                <span className="font-head text-[15px] font-bold tracking-tight text-t1">
                  Guardian Stack
                </span>
              </Link>
            </div>

            {children}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Shared field wrapper ─────────────────────────────────────────────────────

export const FIELD_CLS = `
  w-full h-11 px-3.5 rounded-gs-sm
  border border-gs-line
  bg-surface text-t1 text-[13.5px] font-body
  placeholder:text-t4
  outline-none transition-all duration-150
  focus:border-brand focus:ring-2 focus:ring-brand/10 focus:bg-surface-card
`;

export const FIELD_ICON_CLS = `
  w-full h-11 pl-10 pr-3.5 rounded-gs-sm
  border border-gs-line
  bg-surface text-t1 text-[13.5px] font-body
  placeholder:text-t4
  outline-none transition-all duration-150
  focus:border-brand focus:ring-2 focus:ring-brand/10 focus:bg-surface-card
`;

export const LABEL_CLS = "block text-[11.5px] font-semibold uppercase tracking-[0.06em] text-t3 mb-1.5";

export const BTN_CLS = `
  w-full h-11 rounded-gs
  bg-brand hover:bg-brand-hover
  text-white text-[13.5px] font-semibold font-body
  transition-all duration-150 hover:-translate-y-px
  hover:shadow-[0_6px_20px_rgba(232,92,13,0.28)]
  disabled:opacity-40 disabled:cursor-not-allowed disabled:translate-y-0 disabled:shadow-none
  border-none cursor-pointer
  flex items-center justify-center gap-2
`;