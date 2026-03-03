"use client";

import { Badge } from "@/components/ui/badge";
import { ShieldCheck } from "lucide-react";

interface TopBarProps {
  isFetching: boolean;
}

export function TopBar({ isFetching }: TopBarProps) {
  return (
    <header className="flex items-center gap-3 px-4 md:px-6 py-3 border-b border-border bg-background/95 backdrop-blur-md shrink-0 z-20">
      {/* Logo / Branding */}
      <div className="flex items-center gap-2.5">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-linear-to-br from-blue-700 to-blue-500 shrink-0">
          <ShieldCheck className="h-4 w-4 text-white" />
        </div>
        <div className="leading-none">
          <p className="text-sm font-extrabold tracking-tight text-foreground">
            Guardian Stack
          </p>
          <p className="text-[10px] font-medium tracking-widest uppercase text-muted-foreground/60">
            Forensic Audit Console
          </p>
        </div>
      </div>

      {/* MFA Badge */}
      <Badge
        variant="outline"
        className="border-destructive/40 bg-destructive/8 text-destructive text-[10px] font-bold tracking-widest uppercase"
      >
        Master Admin · MFA Verified
      </Badge>

      {/* Refresh indicator */}
      {isFetching && (
        <span className="text-[10px] font-mono text-muted-foreground/50 tracking-wide animate-pulse">
          ↻ refreshing…
        </span>
      )}

      {/* Route hint */}
      <span className="ml-auto hidden md:block text-[10px] font-mono text-muted-foreground/25 select-none">
        /master-admin/audit/users
      </span>
    </header>
  );
}