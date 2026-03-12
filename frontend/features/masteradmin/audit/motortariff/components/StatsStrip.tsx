"use client";

interface Stats {
  total:         number;
  deactivations: number;
  creations:     number;
  deletions:     number;
}

interface StatsStripProps {
  stats: Stats;
}

function StatCell({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div className="flex flex-col items-center gap-0.5 px-5 py-2 border-r border-gs-line last:border-r-0">
      <span className={`font-body text-lg font-bold tabular-nums ${accent ?? "text-t1"}`}>
        {value.toLocaleString()}
      </span>
      <span className="font-body text-[10px] text-t4 tracking-wide uppercase whitespace-nowrap">
        {label}
      </span>
    </div>
  );
}

export function StatsStrip({ stats }: StatsStripProps) {
  return (
    <div className="flex items-stretch border-b border-gs-line bg-surface-2/40 shrink-0 overflow-x-auto">
      <StatCell label="Total Revisions" value={stats.total} />
      <StatCell label="Creations"       value={stats.creations}     accent="text-gs-green" />
      <StatCell label="Deactivations"   value={stats.deactivations} accent="text-amber-500" />
      <StatCell label="Deletions"       value={stats.deletions}     accent="text-destructive" />
    </div>
  );
}