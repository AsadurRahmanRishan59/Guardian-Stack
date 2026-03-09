"use client";

import { useState } from "react";
import { cn } from "@/lib/utils";
import { ChevronDown, ChevronUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import { RolePill, getRoleVariant } from "./UiPrimitives";
import type { AuditDiffDTO, DiffField } from "@/features/masteradmin/audit/user/user.types";

interface DiffTableProps {
  diff:            AuditDiffDTO;
  currentRevision: number;
}

export function DiffTable({ diff, currentRevision }: DiffTableProps) {
  const [showUnchanged, setShowUnchanged] = useState(false);

  const renderValue = (field: DiffField, isNew: boolean) => {
    const val = isNew ? field.currentValue : field.previousValue;

    if (field.fieldType === "ROLES") {
      const roles = val.split(",").map((r) => r.trim()).filter(Boolean);
      if (roles.length === 0)
        return <span className="font-body text-[11px] text-t4">none</span>;
      return (
        <span className="flex flex-wrap">
          {roles.map((r) => {
            if ( isNew && diff.addedRoles.includes(r))   return <RolePill key={r} role={r} variant="added"   />;
            if (!isNew && diff.removedRoles.includes(r)) return <RolePill key={r} role={r} variant="removed" />;
            return <RolePill key={r} role={r} />;
          })}
        </span>
      );
    }

    if (field.fieldType === "BOOLEAN") {
      const cls =
        val === "true"  ? "text-gs-green" :
        val === "false" ? "text-destructive" :
                          "text-t4";
      return (
        <span className={cn("font-body text-xs font-semibold", cls)}>{val}</span>
      );
    }

    return (
      <span className="font-body text-xs text-t2">{val || "—"}</span>
    );
  };

  const renderRow = (f: DiffField, isChanged: boolean) => (
    <tr
      key={f.fieldName}
      className={cn(
        "border-b border-gs-line/50",
        f.critical && isChanged               && "bg-destructive/[0.03]",
        f.fieldName === "roles" && isChanged
          && diff.adminEscalation             && "bg-brand/[0.03]",
      )}
    >
      {/* Field label */}
      <td className="px-3 py-2 whitespace-nowrap">
        <span className="font-body text-[10px] font-semibold text-t4">
          {f.critical && <span className="mr-1 text-[9px]">⚡</span>}
          {f.fieldLabel}
        </span>
      </td>

      {/* Previous value */}
      <td className="px-3 py-2 text-t4">
        {renderValue(f, false)}
      </td>

      {/* New value + changed chip */}
      <td className="px-3 py-2">
        <div className="flex flex-wrap items-center gap-1.5">
          {renderValue(f, true)}
          {isChanged && (
            <span className={cn(
              "text-[9px] font-bold tracking-wider px-1 py-0.5 rounded-gs-sm border",
              "bg-brand-soft border-brand-border text-brand",
            )}>
              ΔCHANGED
            </span>
          )}
          {f.fieldName === "roles" && diff.adminEscalation && (
            <span className="text-xs leading-none">👑</span>
          )}
          {f.critical && isChanged && (
            <span className="text-xs leading-none">🚩</span>
          )}
        </div>
      </td>
    </tr>
  );

  return (
    <div>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse">
          <thead>
            <tr>
              {[
                "Field",
                `Rev #${diff.previousRevisionNumber ?? "—"} (prev)`,
                `Rev #${currentRevision} (new)`,
              ].map((h) => (
                <th
                  key={h}
                  className="text-left px-3 py-2 border-b border-gs-line whitespace-nowrap font-body text-[10px] font-bold tracking-widest uppercase text-t4"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {diff.changedFields.map((f)   => renderRow(f, true))}
            {showUnchanged && diff.unchangedFields.map((f) => renderRow(f, false))}
          </tbody>
        </table>
      </div>

      {diff.unchangedFields.length > 0 && (
        <Button
          variant="ghost"
          size="sm"
          className={cn(
            "w-full rounded-none rounded-b-gs border-t border-gs-line",
            "font-body text-[11px] text-t4 h-8 hover:text-t2 hover:bg-surface-2",
          )}
          onClick={() => setShowUnchanged((v) => !v)}
        >
          {showUnchanged
            ? <ChevronUp   className="h-3 w-3 mr-1" />
            : <ChevronDown className="h-3 w-3 mr-1" />
          }
          {showUnchanged ? "Hide" : "Show"} {diff.unchangedFields.length} unchanged fields
        </Button>
      )}
    </div>
  );
}