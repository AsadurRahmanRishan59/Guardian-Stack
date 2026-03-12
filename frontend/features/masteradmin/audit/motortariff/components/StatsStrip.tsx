"use client";

interface Stats {
  total:         number;   // from backend totalElements — the real count
  deactivations: number;   // page-scoped
  creations:     number;   // page-scoped
  deletions:     number;   // page-scoped
}

interface StatsStripProps {
  stats:    Stats;
  pageSize: number;
}

function StatCell({
  label,
  value,
  accent,
  tooltip,
}: {
  label:    string;
  value:    number;
  accent?:  string;
  tooltip?: string;
}) {
  return (
    <div
      title={tooltip}
      className="flex flex-col items-center gap-0.5 px-5 py-2 border-r border-gs-line last:border-r-0"
    >
      <span className={`font-body text-lg font-bold tabular-nums ${accent ?? "text-t1"}`}>
        {value.toLocaleString()}
      </span>
      <span className="font-body text-[10px] text-t4 tracking-wide uppercase whitespace-nowrap">
        {label}
      </span>
    </div>
  );
}

export function StatsStrip({ stats, pageSize }: StatsStripProps) {
  return (
    <div className="flex items-stretch border-b border-gs-line bg-surface-2/40 shrink-0 overflow-x-auto">
      <StatCell
        label="Total Revisions"
        value={stats.total}
        tooltip="All revisions in the database matching current filters"
      />
      <StatCell
        label={`New (page)`}
        value={stats.creations}
        accent="text-gs-green"
        tooltip={`CREATED events on this page (up to ${pageSize} rows)`}
      />
      <StatCell
        label={`Deactivated (page)`}
        value={stats.deactivations}
        accent="text-amber-500"
        tooltip={`Status toggled to inactive on this page (up to ${pageSize} rows)`}
      />
      <StatCell
        label={`Deleted (page)`}
        value={stats.deletions}
        accent="text-destructive"
        tooltip={`DELETED events on this page (up to ${pageSize} rows)`}
      />
    </div>
  );
}