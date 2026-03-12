"use client";

// app/admin/audit/tariff/page.tsx

import Link from "next/link";
import { motion } from "framer-motion";
import { Car, Globe, HeartPulse, Home, Shield, Briefcase } from "lucide-react";

const modules = [
  {
    title:       "Motor",
    icon:        Car,
    href:        "/admin/audit/tariff/motor-log",
    description: "Full revision history of motor insurance tariff rates — every rate edit, activation, and deletion.",
    available:   true,
  },
//   {
//     title:       "Overseas Medical",
//     icon:        Globe,
//     href:        "/admin/audit/tariff/overseas-log",
//     description: "Audit trail for overseas medical tariff tables.",
//     available:   false,
//   },
//   {
//     title:       "Health",
//     icon:        HeartPulse,
//     href:        "/admin/audit/tariff/health-log",
//     description: "Audit trail for health insurance tariff rates.",
//     available:   false,
//   },
//   {
//     title:       "Home",
//     icon:        Home,
//     href:        "/admin/audit/tariff/home-log",
//     description: "Audit trail for home insurance tariff tables.",
//     available:   false,
//   },
//   {
//     title:       "Term Life",
//     icon:        Shield,
//     href:        "/admin/audit/tariff/life-log",
//     description: "Audit trail for term life tariff rates.",
//     available:   false,
//   },
//   {
//     title:       "SME Business",
//     icon:        Briefcase,
//     href:        "/admin/audit/tariff/sme-log",
//     description: "Audit trail for SME business tariff tables.",
//     available:   false,
//   },
];

export default function TariffAuditIndexPage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="font-head text-[28px] font-bold tracking-tight text-t1">Tariff Audit</h1>
        <p className="text-[14px] text-t3 mt-1">
          Immutable revision history for all regulated tariff tables. Drill into any tariff&apos;s full lifecycle.
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
              {mod.available ? (
                <Link href={mod.href} className="block group" aria-label={`Open ${mod.title} audit`}>
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
                    <div className="mb-4 w-10 h-10 rounded-gs-sm bg-brand-soft border border-brand-border flex items-center justify-center">
                      <Icon className="w-5 h-5 text-brand" />
                    </div>
                    <div className="font-head text-[15px] font-bold tracking-tight text-t1 mb-1.5">{mod.title}</div>
                    <p className="text-[13px] leading-[1.65] text-t3">{mod.description}</p>
                    <div className="mt-4 text-[12px] font-semibold text-brand opacity-0 group-hover:opacity-100 transition-opacity duration-150">
                      Open →
                    </div>
                  </div>
                </Link>
              ) : (
                <div className="
                  relative p-5 rounded-gs overflow-hidden
                  bg-surface-card border border-gs-line/30 opacity-50
                  shadow-[0_1px_4px_rgba(0,0,0,0.02)]
                ">
                  <div className="mb-4 w-10 h-10 rounded-gs-sm bg-surface-3 border border-gs-line flex items-center justify-center">
                    <Icon className="w-5 h-5 text-t4" />
                  </div>
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className="font-head text-[15px] font-bold tracking-tight text-t2">{mod.title}</span>
                    <span className="inline-flex items-center h-4 px-1.5 rounded-[3px] border border-gs-line bg-surface-3 text-[9px] font-bold font-body text-t4 uppercase tracking-wide">
                      Soon
                    </span>
                  </div>
                  <p className="text-[13px] leading-[1.65] text-t4">{mod.description}</p>
                </div>
              )}
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}