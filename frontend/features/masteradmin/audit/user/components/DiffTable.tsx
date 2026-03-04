"use client";

import { useState } from "react";
import { cn } from "@/lib/utils";
import { ChevronDown, ChevronUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import { RolePill, getRoleVariant } from "./UiPrimitives";
import type { AuditDiffDTO, DiffField } from "@/features/masteradmin/audit/user/user.types";

interface DiffTableProps {
  diff: AuditDiffDTO;
  currentRevision: number;
}

export function DiffTable({ diff, currentRevision }: DiffTableProps) {
  const [showUnchanged, setShowUnchanged] = useState(false);

  const renderValue = (field: DiffField, isNew: boolean) => {
    const val = isNew ? field.currentValue : field.previousValue;

    if (field.fieldType === "ROLES") {
      const roles = val.split(",").map((r) => r.trim()).filter(Boolean);
      if (roles.length === 0)
        return <span className="text-[11px] text-muted-foreground/40">none</span>;
      return (
        <span className="flex flex-wrap">
          {roles.map((r) => {
            // Diff-aware: added/removed takes priority; otherwise derive from role type
            if (isNew  && diff.addedRoles.includes(r))   return <RolePill key={r} role={r} variant="added"   />;
            if (!isNew && diff.removedRoles.includes(r)) return <RolePill key={r} role={r} variant="removed" />;
            return <RolePill key={r} role={r} />;
          })}
        </span>
      );
    }

    if (field.fieldType === "BOOLEAN") {
      const color =
        val === "true"
          ? "text-green-400"
          : val === "false"
          ? "text-red-400"
          : "text-muted-foreground";
      return (
        <span className={cn("font-mono text-xs font-semibold", color)}>{val}</span>
      );
    }

    return (
      <span className="text-xs text-foreground/70">{val || "—"}</span>
    );
  };

  const renderRow = (f: DiffField, isChanged: boolean) => (
    <tr
      key={f.fieldName}
      className={cn(
        "border-b border-border/50",
        f.critical && isChanged && "bg-red-500/[0.03]",
        f.fieldName === "roles" && isChanged && diff.adminEscalation && "bg-amber-400/[0.03]"
      )}
    >
      {/* Field name */}
      <td className="px-3 py-2 whitespace-nowrap">
        <span className="text-[10px] font-semibold font-mono text-muted-foreground/70">
          {f.critical && <span className="mr-1 text-[9px]">⚡</span>}
          {f.fieldLabel}
        </span>
      </td>

      {/* Previous value */}
      <td className="px-3 py-2 text-muted-foreground/50">
        {renderValue(f, false)}
      </td>

      {/* New value + changed indicator */}
      <td className="px-3 py-2">
        <div className="flex flex-wrap items-center gap-1.5">
          {renderValue(f, true)}
          {isChanged && (
            <span className="text-[9px] font-bold tracking-wider px-1 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
              ΔCHANGED
            </span>
          )}
          {f.fieldName === "roles" && diff.adminEscalation && (
            <span className="text-xs">👑</span>
          )}
          {f.critical && isChanged && (
            <span className="text-xs">🚩</span>
          )}
        </div>
      </td>
    </tr>
  );

  return (
    <div>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-xs font-mono">
          <thead>
            <tr>
              {[
                "Field",
                `Rev #${diff.previousRevisionNumber ?? "—"} (prev)`,
                `Rev #${currentRevision} (new)`,
              ].map((h) => (
                <th
                  key={h}
                  className="text-left px-3 py-2 text-[10px] font-bold tracking-widest uppercase text-muted-foreground/40 border-b border-border whitespace-nowrap"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {diff.changedFields.map((f) => renderRow(f, true))}
            {showUnchanged && diff.unchangedFields.map((f) => renderRow(f, false))}
          </tbody>
        </table>
      </div>

      {diff.unchangedFields.length > 0 && (
        <Button
          variant="ghost"
          size="sm"
          className="w-full rounded-none rounded-b-lg border-t border-border text-[11px] text-muted-foreground/50 h-8 font-mono"
          onClick={() => setShowUnchanged((v) => !v)}
        >
          {showUnchanged ? (
            <ChevronUp className="h-3 w-3 mr-1" />
          ) : (
            <ChevronDown className="h-3 w-3 mr-1" />
          )}
          {showUnchanged ? "Hide" : "Show"} {diff.unchangedFields.length} unchanged fields
        </Button>
      )}
    </div>
  );
}