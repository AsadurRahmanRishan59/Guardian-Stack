"use client";

// app/(authenticated)/admin/master-data/tariffs/motor/page.tsx

import Link from "next/link";
import { motion } from "framer-motion";
import { BarChart3, FileText, Settings2, Car } from "lucide-react";

const sections = [
  {
    title:       "Rate Table",
    icon:        BarChart3,
    href:        "/admin/master-data/tariffs/motor/rate-table",
    description: "View, create, edit, and deactivate motor tariff rate entries. Covers all vehicle types, groups, and CC categories across Private, Motorcycle, and Commercial classifications.",
    available:   true,
    cta:         "Manage rates →",
  },
  {
    title:       "Policy Terms",
    icon:        FileText,
    href:        "/admin/master-data/tariffs/motor/policy-terms",
    description: "Define coverage inclusions, exclusions, endorsements, and standard policy wording for each motor tariff category.",
    available:   false,
    cta:         null,
  },
  {
    title:       "Configuration",
    icon:        Settings2,
    href:        "/admin/master-data/tariffs/motor/config",
    description: "System-level settings for motor tariff behaviour — rounding rules, effective dates, regulatory filing metadata, and rate-change approval workflows.",
    available:   false,
    cta:         null,
  },
];

export default function MotorTariffIndexPage() {
  return (
    <div className="space-y-8">

      {/* Breadcrumb header */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <div className="w-8 h-8 rounded-gs-sm bg-brand-soft border border-brand-border flex items-center justify-center shrink-0">
            <Car className="w-4 h-4 text-brand" />
          </div>
          <div>
            <p className="text-[11px] font-body text-t4 font-semibold tracking-widest uppercase">
              Master Data · Tariffs
            </p>
            <h1 className="font-head text-[24px] font-bold tracking-tight text-t1 leading-tight">
              Motor Insurance
            </h1>
          </div>
        </div>
        <p className="text-[14px] text-t3 mt-2 ml-10">
          IDRA-regulated premium rate tables for private vehicles, motorcycles, and commercial fleet.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
        {sections.map((s, i) => {
          const Icon = s.icon;
          return (
            <motion.div
              key={s.title}
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.08, duration: 0.4 }}
            >
              {s.available ? (
                <Link href={s.href} className="block group" aria-label={`Open ${s.title}`}>
                  <div className="
                    relative p-5 rounded-gs overflow-hidden cursor-pointer
                    bg-surface-card border border-gs-line/50
                    shadow-[0_1px_4px_rgba(0,0,0,0.04)]
                    transition-all duration-200
                    hover:border-brand-border
                    hover:shadow-[0_4px_20px_rgba(232,92,13,0.10)]
                    hover:-translate-y-0.5
                  ">
                    <div className="absolute inset-x-0 top-0 h-0.5 bg-brand rounded-t-gs opacity-0 group-hover:opacity-100 transition-opacity duration-200" />
                    <div className="mb-4 w-10 h-10 rounded-gs-sm bg-brand-soft border border-brand-border flex items-center justify-center">
                      <Icon className="w-5 h-5 text-brand" />
                    </div>
                    <div className="font-head text-[15px] font-bold tracking-tight text-t1 mb-1.5">
                      {s.title}
                    </div>
                    <p className="text-[13px] leading-[1.65] text-t3">{s.description}</p>
                    <div className="mt-4 text-[12px] font-semibold text-brand opacity-0 group-hover:opacity-100 transition-opacity duration-150">
                      {s.cta}
                    </div>
                  </div>
                </Link>
              ) : (
                <div className="
                  relative p-5 rounded-gs overflow-hidden
                  bg-surface-card border border-gs-line/30 opacity-50
                  shadow-[0_1px_4px_rgba(0,0,0,0.02)]
                ">
                  <div className="flex items-start justify-between mb-4">
                    <div className="w-10 h-10 rounded-gs-sm bg-surface-3 border border-gs-line flex items-center justify-center">
                      <Icon className="w-5 h-5 text-t4" />
                    </div>
                    <span className="inline-flex items-center h-5 px-2 rounded-full bg-surface-3 border border-gs-line text-[10px] font-bold font-body text-t4 uppercase tracking-wide">
                      Soon
                    </span>
                  </div>
                  <div className="font-head text-[15px] font-bold tracking-tight text-t2 mb-1.5">
                    {s.title}
                  </div>
                  <p className="text-[13px] leading-[1.65] text-t4">{s.description}</p>
                </div>
              )}
            </motion.div>
          );
        })}
      </div>

    </div>
  );
}