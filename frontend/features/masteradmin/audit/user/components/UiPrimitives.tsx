"use client";

import { cn } from "@/lib/utils";
import { AppRole } from "@/types/auth.types";
import { AlertTriangle } from "lucide-react";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const TRUSTED_IP_PREFIXES = ["192.168.", "10.0.", "172.16."];

export function isKnownIP(ip: string) {
  return TRUSTED_IP_PREFIXES.some((p) => ip?.startsWith(p));
}

export function formatTs(iso: string) {
  if (!iso) return { date: "—", time: "—" };
  const d = new Date(iso);
  return {
    date: d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }),
    time: d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
  };
}

// ─── RevBadge ─────────────────────────────────────────────────────────────────

export const REV_CFG = {
  CREATED:  { label: "ADD", icon: "+",  className: "text-gs-green    bg-gs-green-bg      border-gs-green/30"    },
  MODIFIED: { label: "MOD", icon: "✎", className: "text-brand       bg-brand-soft       border-brand-border"   },
  DELETED:  { label: "DEL", icon: "✕",  className: "text-destructive  bg-destructive/10  border-destructive/25" },
} as const;

export function RevBadge({ type }: { type: string }) {
  const cfg = REV_CFG[type as keyof typeof REV_CFG] ?? REV_CFG.MODIFIED;
  return (
    <span className={cn(
      "inline-flex items-center gap-1 px-1.5 py-0.5 rounded-gs-sm border",
      "text-[10px] font-bold font-body tracking-wide",
      cfg.className
    )}>
      {cfg.icon} {cfg.label}
    </span>
  );
}

// ─── IPLabel ──────────────────────────────────────────────────────────────────

export function IPLabel({ ip }: { ip: string }) {
  const known = isKnownIP(ip);
  return (
    <span className={cn(
      "inline-flex items-center gap-1 font-body text-[11px]",
      known ? "text-t3" : "text-brand"
    )}>
      {!known && <AlertTriangle className="h-3 w-3 shrink-0" />}
      {ip}
      {!known && (
        <span className="text-[9px] font-bold tracking-wider text-brand/60">EXTERNAL</span>
      )}
    </span>
  );
}

// ─── RolePill ─────────────────────────────────────────────────────────────────

export type RoleVariant = "neutral" | "added" | "removed" | "master" | "admin" | "employee" | "user";

const ROLE_STYLES: Record<RoleVariant, string> = {
  neutral:  "text-t3          bg-surface-3        border-gs-line",
  added:    "text-gs-green    bg-gs-green-bg      border-gs-green/30",
  removed:  "text-destructive bg-destructive/10   border-destructive/25",
  master:   "text-brand       bg-brand-soft       border-brand-border",
  admin:    "text-brand       bg-brand-soft/60    border-brand-border/60",
  employee: "text-t2          bg-surface-3        border-gs-line-2",
  user:     "text-t3          bg-surface-2        border-gs-line",
};

export function getRoleVariant(role: string): RoleVariant {
  switch (role) {
    case AppRole.MASTER_ADMIN: return "master";
    case AppRole.ADMIN:        return "admin";
    case AppRole.EMPLOYEE:     return "employee";
    case AppRole.USER:         return "user";
    default:                   return "neutral";
  }
}

export function RolePill({ role, variant }: { role: string; variant?: RoleVariant }) {
  const v = variant ?? getRoleVariant(role);
  return (
    <span className={cn(
      "inline-block px-1.5 py-0.5 rounded-gs-sm border mx-0.5 my-0.5",
      "text-[10px] font-body font-semibold",
      ROLE_STYLES[v]
    )}>
      {role.replace("ROLE_", "")}
    </span>
  );
}