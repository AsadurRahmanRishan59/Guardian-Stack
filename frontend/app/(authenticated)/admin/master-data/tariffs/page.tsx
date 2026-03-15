"use client";

// app/(authenticated)/admin/master-data/tariffs/page.tsx

import Link from "next/link";
import { motion } from "framer-motion";
import { Car, Globe, HeartPulse, Home, Shield, Briefcase } from "lucide-react";

const tariffs = [
  {
    title:       "Motor",
    icon:        Car,
    href:        "/admin/master-data/tariffs/motor",
    description: "IDRA-regulated motor insurance rates. Private vehicles, motorcycles, and commercial fleet tariffs.",
    available:   true,
    stats:       "3 types · Private, Motorcycle, Commercial",
  },
  {
    title:       "Overseas Medical",
    icon:        Globe,
    href:        "/admin/master-data/tariffs/overseas",
    description: "International medical coverage tariffs for Bangladeshi travellers across 190+ countries.",
    available:   false,
    stats:       null,
  },
  {
    title:       "Health",
    icon:        HeartPulse,
    href:        "/admin/master-data/tariffs/health",
    description: "In-patient, out-patient, and specialist coverage tariffs for individual and family plans.",
    available:   false,
    stats:       null,
  },
  {
    title:       "Home",
    icon:        Home,
    href:        "/admin/master-data/tariffs/home",
    description: "Building and contents tariffs for homeowners and renters — fire, flood, theft, and structural.",
    available:   false,
    stats:       null,
  },
  {
    title:       "Term Life",
    icon:        Shield,
    href:        "/admin/master-data/tariffs/life",
    description: "Pure term life tariffs — mortality rates and premium bands by age, tenure, and sum assured.",
    available:   false,
    stats:       null,
  },
  {
    title:       "SME Business",
    icon:        Briefcase,
    href:        "/admin/master-data/tariffs/sme",
    description: "Commercial tariffs for property, liability, employee health, and goods-in-transit cover.",
    available:   false,
    stats:       null,
  },
];

export default function TariffsIndexPage() {
  return (
    <div className="space-y-8">

      <div>
        <h1 className="font-head text-[28px] font-bold tracking-tight text-t1">Tariffs</h1>
        <p className="text-[14px] text-t3 mt-1">
          Manage IDRA-regulated premium rate tables for all insurance products.
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
        {tariffs.map((t, i) => {
          const Icon = t.icon;
          return (
            <motion.div
              key={t.title}
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.07, duration: 0.4 }}
            >
              {t.available ? (
                <Link href={t.href} className="block group" aria-label={`Open ${t.title} tariffs`}>
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

                    <div className="flex items-start justify-between mb-4">
                      <div className="w-10 h-10 rounded-gs-sm bg-brand-soft border border-brand-border flex items-center justify-center">
                        <Icon className="w-5 h-5 text-brand" />
                      </div>
                      <span className="inline-flex items-center gap-1 h-5 px-2 rounded-full bg-gs-green-bg border border-gs-green/30 text-[10px] font-bold font-body text-gs-green uppercase tracking-wide">
                        <span className="h-1.5 w-1.5 rounded-full bg-gs-green" />
                        Live
                      </span>
                    </div>

                    <div className="font-head text-[15px] font-bold tracking-tight text-t1 mb-1.5">
                      {t.title}
                    </div>
                    <p className="text-[13px] leading-[1.65] text-t3 mb-3">{t.description}</p>

                    {t.stats && (
                      <p className="text-[11px] font-body text-t4 border-t border-gs-line pt-2.5">
                        {t.stats}
                      </p>
                    )}

                    <div className="mt-3 text-[12px] font-semibold text-brand opacity-0 group-hover:opacity-100 transition-opacity duration-150">
                      Manage →
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
                    {t.title}
                  </div>
                  <p className="text-[13px] leading-[1.65] text-t4">{t.description}</p>
                </div>
              )}
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}