"use client";

import { useState } from "react";
import { cn } from "@/lib/utils";
import { ChevronDown, ChevronUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { MotorTariffAuditDiffDTO, DiffField } from "@/features/masteradmin/audit/motortariff/motortariff_audit_types";

interface DiffTableProps {
  diff:            MotorTariffAuditDiffDTO;
  currentRevision: number;
}

// ─── Value renderer ───────────────────────────────────────────────────────────

function renderValue(field: DiffField, isNew: boolean) {
  const val = isNew ? field.currentValue : field.previousValue;

  if (field.fieldType === "BOOLEAN") {
    const cls =
      val === "true"  ? "text-gs-green" :
      val === "false" ? "text-destructive" : "text-t4";
    return <span className={cn("font-body text-xs font-semibold", cls)}>{val}</span>;
  }

  if (field.fieldType === "DECIMAL") {
    const num = parseFloat(val);
    return (
      <span className="font-body text-xs tabular-nums text-t1">
        {isNaN(num) ? val : `৳ ${num.toLocaleString("en-BD", { minimumFractionDigits: 2 })}`}
      </span>
    );
  }

  if (field.fieldType === "PERCENT") {
    return (
      <span className="font-body text-xs tabular-nums text-t1">
        {val === "—" ? val : `${val}%`}
      </span>
    );
  }

  return <span className="font-body text-xs text-t1 break-all">{val || "—"}</span>;
}

// ─── Single row ───────────────────────────────────────────────────────────────

function DiffRow({ field, isSummary }: { field: DiffField; isSummary: boolean }) {
  return (
    <tr className={cn(
      "border-b border-gs-line last:border-0 transition-colors",
      field.critical && "bg-amber-500/5",
      isSummary && "opacity-50",
    )}>
      <td className="py-1.5 pl-3 pr-2 w-1/3">
        <div className="flex items-center gap-1.5">
          {field.critical && (
            <span className="h-1.5 w-1.5 rounded-full bg-amber-500 shrink-0" />
          )}
          <span className="font-body text-[11px] text-t3 truncate">{field.fieldLabel}</span>
        </div>
      </td>
      <td className="py-1.5 px-2 w-1/3">
        <div className={cn(!isSummary && "line-through opacity-50")}>
          {renderValue(field, false)}
        </div>
      </td>
      <td className="py-1.5 pl-2 pr-3 w-1/3">
        {renderValue(field, true)}
      </td>
    </tr>
  );
}

// ─── DiffTable ────────────────────────────────────────────────────────────────

export function DiffTable({ diff, currentRevision }: DiffTableProps) {
  const [showUnchanged, setShowUnchanged] = useState(false);

  const hasChanged   = diff.changedFields.length   > 0;
  const hasUnchanged = diff.unchangedFields.length > 0;

  return (
    <div className="space-y-3">

      {/* Changed fields */}
      {hasChanged ? (
        <div>
          <div className="px-3 py-1.5 bg-surface-2/50 border-b border-gs-line">
            <span className="font-body text-[10px] font-bold tracking-widest uppercase text-t4">
              Changed ({diff.changedFields.length})
            </span>
            {diff.criticalChange && (
              <span className="ml-2 inline-flex items-center h-4 px-1.5 rounded-[3px] border bg-amber-500/10 text-amber-600 border-amber-500/30 text-[9px] font-bold font-body uppercase">
                ⚠ Critical
              </span>
            )}
          </div>
          <table className="w-full table-fixed">
            <thead>
              <tr className="border-b border-gs-line bg-surface-3/30">
                <th className="py-1 pl-3 text-left font-body text-[9px] font-bold tracking-widest uppercase text-t4 w-1/3">Field</th>
                <th className="py-1 px-2 text-left font-body text-[9px] font-bold tracking-widest uppercase text-t4 w-1/3">
                  Before #{diff.previousRevisionNumber ?? "—"}
                </th>
                <th className="py-1 pl-2 pr-3 text-left font-body text-[9px] font-bold tracking-widest uppercase text-t4 w-1/3">
                  After #{currentRevision}
                </th>
              </tr>
            </thead>
            <tbody>
              {diff.changedFields.map((f) => (
                <DiffRow key={f.fieldName} field={f} isSummary={false} />
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="px-3 py-3 text-center">
          <span className="font-body text-xs text-t4">No field changes in this revision.</span>
        </div>
      )}

      {/* Unchanged fields toggle */}
      {hasUnchanged && (
        <div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowUnchanged((v) => !v)}
            className="w-full h-7 rounded-none justify-between px-3 text-[10px] font-body text-t4 hover:text-t2 hover:bg-surface-2 border-t border-gs-line"
          >
            <span className="font-bold tracking-widest uppercase">
              Unchanged ({diff.unchangedFields.length})
            </span>
            {showUnchanged ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
          </Button>
          {showUnchanged && (
            <table className="w-full table-fixed opacity-60">
              <tbody>
                {diff.unchangedFields.map((f) => (
                  <DiffRow key={f.fieldName} field={f} isSummary={true} />
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}