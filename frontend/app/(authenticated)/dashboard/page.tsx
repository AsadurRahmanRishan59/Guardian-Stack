"use client";

// app/(authenticated)/page.tsx

import Link from "next/link";
import { motion } from "framer-motion";
import { Shield } from "lucide-react";
import { AppRole } from "@/types/auth.types";

// ✅ Context — no useCurrentUser() call
import { useUser } from "@/app/(authenticated)/layout";

const modules = [
  {
    title:       "Admin",
    icon:        Shield,
    href:        "/admin",
    description: "Manage users, roles, permissions and system configurations.",
    roles:       [AppRole.ADMIN, AppRole.MASTER_ADMIN],
  },
];

export default function HomePage() {
  const { user, isLoading } = useUser();

  const allowed = modules.filter((m) =>
    m.roles.some((r) => user?.roles?.includes(r))
  );

  return (
    <div className="space-y-8">
      <div>
        <h1 className="font-head text-[28px] font-bold tracking-tight text-t1">Dashboard</h1>
        <p className="text-[14px] text-t3 mt-1">Select a module to get started.</p>
      </div>

      {isLoading ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-5">
          {[1, 2].map((i) => (
            <div key={i} className="h-36 rounded-gs bg-surface-card border border-gs-line/50 animate-pulse" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-5">
          {allowed.map((mod, i) => {
            const Icon = mod.icon;
            return (
              <motion.div
                key={mod.title}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.08, duration: 0.4 }}
              >
                <Link href={mod.href} className="block group">
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
                      Open module →
                    </div>
                  </div>
                </Link>
              </motion.div>
            );
          })}
        </div>
      )}
    </div>
  );
}