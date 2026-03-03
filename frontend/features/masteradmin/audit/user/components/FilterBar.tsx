"use client";

import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { X, ChevronLeft, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";
import type { AuditFilterRequest } from "@/features/masteradmin/audit/user/user.types";

const REV_CFG = {
  CREATED:  { label: "ADD", icon: "+",  activeClass: "border-green-500  bg-green-500/10  text-green-400",  inactiveClass: "border-border text-muted-foreground" },
  MODIFIED: { label: "MOD", icon: "✎", activeClass: "border-blue-500   bg-blue-500/10   text-blue-400",   inactiveClass: "border-border text-muted-foreground" },
  DELETED:  { label: "DEL", icon: "🗑", activeClass: "border-red-500    bg-red-500/10    text-red-400",    inactiveClass: "border-border text-muted-foreground" },
} as const;

interface FilterBarProps {
  filter: AuditFilterRequest;
  onUpdate: (patch: Partial<AuditFilterRequest>) => void;
  onClear: () => void;
  hasActiveFilters: boolean;
  totalElements: number;
  totalPages: number;
  onPageChange: (page: number) => void;
}

export function FilterBar({
  filter,
  onUpdate,
  onClear,
  hasActiveFilters,
  totalElements,
  totalPages,
  onPageChange,
}: FilterBarProps) {
  const activeRevTypes: string[] = filter.revisionTypes
    ? filter.revisionTypes.split(",").filter(Boolean)
    : [];

  const toggleRevType = (type: string) => {
    const next = activeRevTypes.includes(type)
      ? activeRevTypes.filter((t) => t !== type)
      : [...activeRevTypes, type];
    onUpdate({ revisionTypes: next.join(",") || undefined });
  };

  const currentPage = filter.page ?? 0;

  return (
    <div className="flex flex-wrap items-center gap-2 px-4 md:px-6 py-2.5 border-b border-border bg-background/60 shrink-0">
      {/* Label */}
      <span className="text-[9px] font-bold tracking-widest uppercase text-muted-foreground/40 mr-1 hidden sm:block">
        Filter
      </span>

      {/* Text filters */}
      <div className="flex flex-wrap gap-2">
        {([
          { key: "email",     placeholder: "Email / User ID",   className: "w-44" },
          { key: "changedBy", placeholder: "Actor (changedBy)", className: "w-40" },
          { key: "ipAddress", placeholder: "IP or prefix",      className: "w-32" },
        ] as const).map(({ key, placeholder, className }) => (
          <Input
            key={key}
            value={(filter as Record<string, string>)[key] ?? ""}
            onChange={(e) => onUpdate({ [key]: e.target.value || undefined })}
            placeholder={placeholder}
            className={cn(
              "h-7 text-xs font-mono bg-muted/40 border-border placeholder:text-muted-foreground/25 focus-visible:ring-1 focus-visible:ring-blue-500",
              className
            )}
          />
        ))}
      </div>

      {/* Rev-type toggles */}
      <div className="flex gap-1.5">
        {(["CREATED", "MODIFIED", "DELETED"] as const).map((type) => {
          const cfg = REV_CFG[type];
          const active = activeRevTypes.includes(type);
          return (
            <button
              key={type}
              onClick={() => toggleRevType(type)}
              className={cn(
                "h-7 px-2.5 rounded-md border text-[10px] font-bold font-mono tracking-wide transition-all duration-100",
                active ? cfg.activeClass : cfg.inactiveClass,
                "hover:opacity-80"
              )}
            >
              {cfg.icon} {type}
            </button>
          );
        })}
      </div>

      {/* Clear */}
      {hasActiveFilters && (
        <Button
          variant="ghost"
          size="sm"
          onClick={onClear}
          className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground"
        >
          <X className="h-3 w-3 mr-1" />
          Clear
        </Button>
      )}

      {/* Right side: count + pagination */}
      <div className="ml-auto flex items-center gap-3">
        <Badge variant="secondary" className="text-[10px] font-mono font-normal hidden sm:flex">
          {totalElements.toLocaleString()} events
        </Badge>

        {totalPages > 1 && (
          <div className="flex items-center gap-1">
            <Button
              variant="outline"
              size="icon"
              className="h-6 w-6"
              onClick={() => onPageChange(currentPage - 1)}
              disabled={currentPage === 0}
            >
              <ChevronLeft className="h-3 w-3" />
            </Button>
            <span className="text-[10px] font-mono text-muted-foreground min-w-12 text-center">
              {currentPage + 1} / {totalPages}
            </span>
            <Button
              variant="outline"
              size="icon"
              className="h-6 w-6"
              onClick={() => onPageChange(currentPage + 1)}
              disabled={currentPage >= totalPages - 1}
            >
              <ChevronRight className="h-3 w-3" />
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}