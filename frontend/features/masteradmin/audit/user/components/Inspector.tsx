"use client";

import { useRevisionDetail } from "@/features/masteradmin/audit/user/user.react.query";
import type { AuditTimelineItemDTO } from "@/features/masteradmin/audit/user/user.types";
import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { RevBadge, IPLabel, RolePill, formatTs } from "./UiPrimitives";
import { DiffTable } from "./DiffTable";

// ─── Empty State ──────────────────────────────────────────────────────────────

function InspectorEmpty() {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 p-8">
      <span className="text-4xl">🔍</span>
      <p className="text-sm text-muted-foreground text-center max-w-45 leading-relaxed">
        Select a revision from the timeline to inspect
      </p>
    </div>
  );
}

// ─── Loading State ────────────────────────────────────────────────────────────

function InspectorLoading({ revNum }: { revNum: number }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 p-8">
      <span className="text-[11px] font-mono text-muted-foreground/40 tracking-widest uppercase">
        Loading Revision #{revNum}…
      </span>
      <div className="w-48 h-0.5 bg-muted overflow-hidden rounded-full">
        <div className="h-full w-2/5 bg-blue-500 rounded-full animate-[slide_1.2s_ease-in-out_infinite]" />
      </div>
    </div>
  );
}

// ─── Error State ──────────────────────────────────────────────────────────────

function InspectorError() {
  return (
    <div className="flex h-full items-center justify-center p-8">
      <p className="text-sm text-destructive">Failed to load revision details.</p>
    </div>
  );
}

// ─── Section wrapper ──────────────────────────────────────────────────────────

function Section({
  label,
  children,
  className,
}: {
  label: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "rounded-lg border border-border bg-card overflow-hidden",
        className
      )}
    >
      <div className="px-4 py-2.5 border-b border-border">
        <span className="text-[10px] font-bold tracking-widest uppercase text-muted-foreground/40">
          {label}
        </span>
      </div>
      {children}
    </div>
  );
}

// ─── Identity rows ────────────────────────────────────────────────────────────

function IdentityRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string | number | null;
  mono?: boolean;
}) {
  return (
    <div className="flex items-baseline gap-2 mb-2 last:mb-0">
      <span className="text-[11px] text-muted-foreground/50 min-w-[72px] shrink-0">{label}</span>
      <span
        className={cn(
          "text-xs text-foreground/80 break-all",
          mono && "font-mono"
        )}
      >
        {value ?? "—"}
      </span>
    </div>
  );
}

// ─── Inspector ────────────────────────────────────────────────────────────────

interface InspectorProps {
  selectedItem: AuditTimelineItemDTO | null;
}

export function Inspector({ selectedItem }: InspectorProps) {
  const { data: detail, isLoading, isError } = useRevisionDetail(
    selectedItem?.userId,
    selectedItem?.revisionNumber
  );

  if (!selectedItem) return <InspectorEmpty />;
  if (isLoading) return <InspectorLoading revNum={selectedItem.revisionNumber} />;
  if (isError || !detail) return <InspectorError />;

  const { date, time } = formatTs(detail.timestamp);
  const data = detail.data ?? detail; // handle ApiResponse wrapper

  return (
    <div className="p-4 md:p-5 space-y-3 overflow-y-auto">
      {/* ── Header ── */}
      <div className="mb-1">
        <div className="flex items-center gap-2 mb-0.5 flex-wrap">
          <span className="text-[10px] font-mono font-medium tracking-widest uppercase text-muted-foreground/40">
            Revision
          </span>
          <span className="font-mono text-xl font-bold text-blue-400">
            #{data.revisionNumber}
          </span>
          <RevBadge type={data.revisionType} />
        </div>
        <p className="font-mono text-[11px] text-muted-foreground/50">
          {date} · {time}
        </p>
      </div>

      {/* ── Alert banners ── */}
      {data.diff?.criticalChange && (
        <Alert variant="destructive" className="border-red-500/30 bg-red-500/5">
          <span className="mr-2">🚩</span>
          <AlertTitle className="text-xs font-bold text-red-400">Critical State Change</AlertTitle>
          <AlertDescription className="text-[11px] text-red-400/60 mt-1">
            {data.accountLocked && "Account is locked. "}
            {!data.enabled && "Account is disabled."}
          </AlertDescription>
        </Alert>
      )}
      {data.diff?.adminEscalation && (
        <Alert className="border-amber-400/30 bg-amber-400/5">
          <span className="mr-2">👑</span>
          <AlertTitle className="text-xs font-bold text-amber-400">Admin Role Escalation</AlertTitle>
          <AlertDescription className="text-[11px] text-amber-400/60 mt-1">
            ROLE_ADMIN was granted in this revision.
          </AlertDescription>
        </Alert>
      )}

      {/* ── Identity ── */}
      <Section label="Identity">
        <div className="px-4 py-3">
          <IdentityRow label="User ID"  value={data.userId}      mono />
          <IdentityRow label="Username" value={data.username}         />
          <IdentityRow label="Email"    value={data.email}            />
          <IdentityRow label="Sign-up"  value={data.signUpMethod} mono />
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[11px] text-muted-foreground/50 min-w-[72px]">IP</span>
            <IPLabel ip={data.ipAddress} />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-muted-foreground/50 min-w-[72px]">Actor</span>
            <span className="text-xs font-semibold text-foreground/90">{data.changedBy}</span>
            {data.diff?.previousChangedBy && (
              <span className="text-[10px] text-muted-foreground/40">
                (prev by {data.diff.previousChangedBy})
              </span>
            )}
          </div>
        </div>
      </Section>

      {/* ── Delta ── */}
      <Section label={`Δ Delta · ${data.diff?.changedFields.length ?? 0} field${(data.diff?.changedFields.length ?? 0) !== 1 ? "s" : ""} changed`}>
        {data.diff ? (
          <DiffTable diff={data.diff} currentRevision={data.revisionNumber} />
        ) : (
          <div className="px-4 py-5 text-xs text-muted-foreground/40 text-center font-mono">
            First revision — no previous state to compare.
          </div>
        )}
      </Section>

      {/* ── Current Roles ── */}
      <Section label="Current Roles">
        <div className="px-4 py-3 flex flex-wrap">
          {data.roles.length > 0
            ? data.roles.map((r: string) => (
                <RolePill
                  key={r}
                  role={r}
                  variant={r === "ROLE_ADMIN" ? "admin" : "neutral"}
                />
              ))
            : <span className="text-xs text-muted-foreground/40">No roles assigned</span>
          }
        </div>
      </Section>
    </div>
  );
}