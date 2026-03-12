"use client";

import { Activity } from "lucide-react";

interface TopBarProps {
  isFetching?: boolean;
}

export function TopBar({ isFetching }: TopBarProps) {
  return (
    <div className="flex items-center justify-between px-6 py-3 border-b border-gs-line bg-surface-card shrink-0">
      <div className="flex items-center gap-3">
        <Activity className="w-4 h-4 text-brand" />
        <span className="font-body text-sm font-semibold text-t1 tracking-tight">
          Motor Tariff — Audit History
        </span>
        {isFetching && (
          <span className="font-body text-[10px] text-t4 animate-pulse tracking-widest uppercase">
            refreshing…
          </span>
        )}
      </div>
      <span className="font-body text-[11px] text-t4">
        Hibernate Envers · Read-only
      </span>
    </div>
  );
}