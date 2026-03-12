"use client";

// app/admin/audit/page.tsx

import Link from "next/link";
import { motion } from "framer-motion";
import { ScrollText, LogIn, Receipt } from "lucide-react";

const modules = [
  {
    title:       "User Log",
    icon:        ScrollText,
    href:        "/admin/audit/user-log",
    description: "Full revision history of every user account — field-level diffs, role changes, and account status events.",
    badge:       null,
  },
  {
    title:       "Login Log",
    icon:        LogIn,
    href:        "/admin/audit/login-log",
    description: "Authentication events: successful logins, failures, OTP verifications, and token refreshes.",
    badge:       null,
  },
  {
    title:       "Tariff Audit",
    icon:        Receipt,
    href:        "/admin/audit/tariff",
    description: "Audit trails for regulated tariff tables — track every rate change, activation, and deletion.",
    badge:       "Master Admin",
  },
];

export default function AuditIndexPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="font-head text-[28px] font-bold tracking-tight text-t1">Audit</h1>
        <p className="text-[14px] text-t3 mt-1">
          Immutable revision history powered by Hibernate Envers. Every change is recorded.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
        {modules.map((mod, i) => {
          const Icon = mod.icon;
          return (
            <motion.div
              key={mod.title}
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.08, duration: 0.4 }}
            >
              <Link href={mod.href} className="block group" aria-label={`Open ${mod.title}`}>
                <div className="
                  relative p-5 rounded-gs overflow-hidden cursor-pointer
                  bg-surface-card border border-gs-line/50
                  shadow-[0_1px_4px_rgba(0,0,0,0.04)]
                  transition-all duration-200
                  hover:border-brand-border
                  hover:shadow-[0_4px_20px_rgba(232,92,13,0.10)]
                  hover:-translate-y-0.5
                ">
                  <div className="absolute inset-x-0 top-0 h-[2px] bg-brand rounded-t-gs opacity-0 group-hover:opacity-100 transition-opacity duration-200" />

                  <div className="flex items-start justify-between mb-4">
                    <div className="w-10 h-10 rounded-gs-sm bg-brand-soft border border-brand-border flex items-center justify-center">
                      <Icon className="w-5 h-5 text-brand" />
                    </div>
                    {mod.badge && (
                      <span className="inline-flex items-center h-5 px-2 rounded-full bg-surface-3 border border-gs-line text-[10px] font-bold font-body text-t4 uppercase tracking-wide">
                        {mod.badge}
                      </span>
                    )}
                  </div>

                  <div className="font-head text-[15px] font-bold tracking-tight text-t1 mb-1.5">
                    {mod.title}
                  </div>
                  <p className="text-[13px] leading-[1.65] text-t3">{mod.description}</p>
                  <div className="mt-4 text-[12px] font-semibold text-brand opacity-0 group-hover:opacity-100 transition-opacity duration-150">
                    Open →
                  </div>
                </div>
              </Link>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}