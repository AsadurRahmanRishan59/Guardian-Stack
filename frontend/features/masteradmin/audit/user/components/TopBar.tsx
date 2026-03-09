"use client";

import { ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";

interface TopBarProps {
  isFetching: boolean;
}

export function TopBar({ isFetching }: TopBarProps) {
  return (
    <header className="flex items-center gap-3 px-4 md:px-5 py-2.5 border-b border-gs-line bg-surface-card shrink-0 z-20">

      {/* Branding */}
      <div className="flex items-center gap-2.5">
        <div className="flex h-8 w-8 items-center justify-center rounded-gs bg-brand shrink-0">
          <ShieldCheck className="h-4 w-4 text-white" />
        </div>
        <div className="leading-none">
          <p className="text-sm font-bold font-head text-t1 tracking-tight">
            Guardian Stack
          </p>
          <p className="text-[10px] font-body font-semibold tracking-widest uppercase text-t4">
            Forensic Audit Console
          </p>
        </div>
      </div>

      {/* Role / MFA badge — uses brand-soft (non-destructive) since this is a
          verified/trusted state, not an error. Destructive red would imply
          something is wrong. Brand-orange reads as "elevated privilege". */}
      <Badge className="border-brand-border bg-brand-soft text-brand text-[10px] font-bold font-body tracking-widest uppercase">
        Master Admin · MFA Verified
      </Badge>

      {/* Live refresh indicator */}
      {isFetching && (
        <span className="text-[10px] font-body text-t4 tracking-wide animate-pulse">
          ↻ refreshing…
        </span>
      )}

      {/* Route hint — lowest visual priority */}
      <span className="ml-auto hidden md:block text-[10px] font-body text-t4/50 select-none tracking-wide">
        /master-admin/audit/users
      </span>
    </header>
  );
}