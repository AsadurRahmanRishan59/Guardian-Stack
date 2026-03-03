"use client";

// ─────────────────────────────────────────────────────────────────────────────
// Guardian Stack — Master Admin Forensic Audit Console
// Path: app/(master-admin)/audit/users/page.tsx
//
// Architecture:
//   LEFT RAIL  → useTimelineItems()   → GET /master-admin/audit/users
//   RIGHT RAIL → useRevisionDetail()  → GET /master-admin/audit/users/{id}/revision/{rev}
//
// The split-DTO pattern means:
//   • Left rail loads instantly (slim DTO, no diff computation)
//   • Right rail loads lazily on click (full DTO + pre-computed diff)
//   • React Query caches revision details forever (forensic data is immutable)
// ─────────────────────────────────────────────────────────────────────────────

import { useState, useCallback, useMemo } from "react";
import {
  useTimelineItems,
  useRevisionDetail,
} from "@/features/masteradmin/audit/user/user.react.query";
import type {
  AuditFilterRequest,
  AuditTimelineItemDTO,
  AuditDiffDTO,
  DiffField,
} from "@/features/masteradmin/audit/user/user.types";

// ─── Constants ───────────────────────────────────────────────────────────────

const TRUSTED_IP_PREFIXES = ["192.168.", "10.0.", "172.16."];
const PAGE_SIZE = 50;

function isKnownIP(ip: string) {
  return TRUSTED_IP_PREFIXES.some((p) => ip?.startsWith(p));
}

function formatTs(iso: string) {
  if (!iso) return { date: "—", time: "—" };
  const d = new Date(iso);
  return {
    date: d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }),
    time: d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
  };
}

// ─── Visual config per revision type ─────────────────────────────────────────

const REV_CFG = {
  CREATED:  { label: "ADD", icon: "+",  color: "#22c55e", bg: "rgba(34,197,94,0.12)",  border: "rgba(34,197,94,0.3)"  },
  MODIFIED: { label: "MOD", icon: "✎", color: "#3b82f6", bg: "rgba(59,130,246,0.12)",  border: "rgba(59,130,246,0.3)" },
  DELETED:  { label: "DEL", icon: "🗑", color: "#ef4444", bg: "rgba(239,68,68,0.12)",  border: "rgba(239,68,68,0.3)"  },
} as const;

// ─────────────────────────────────────────────────────────────────────────────
// Sub-components
// ─────────────────────────────────────────────────────────────────────────────

function RevBadge({ type }: { type: string }) {
  const cfg = REV_CFG[type as keyof typeof REV_CFG] ?? REV_CFG.MODIFIED;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 4,
      padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 700,
      fontFamily: "var(--font-mono)",
      color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.border}`,
      letterSpacing: "0.06em",
    }}>
      {cfg.icon} {cfg.label}
    </span>
  );
}

function IPLabel({ ip }: { ip: string }) {
  const known = isKnownIP(ip);
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 4,
      fontFamily: "var(--font-mono)", fontSize: 11,
      color: known ? "#64748b" : "#f97316",
    }}>
      {!known && <span title="Unrecognised location" style={{ fontSize: 12 }}>⚠</span>}
      {ip}
      {!known && <span style={{ fontSize: 9, color: "#f9731680", marginLeft: 2 }}>EXTERNAL</span>}
    </span>
  );
}

function RolePill({ role, variant = "neutral" }: { role: string; variant?: "neutral" | "added" | "removed" | "admin" }) {
  const styles = {
    neutral: { bg: "rgba(148,163,184,0.1)",  color: "#94a3b8", border: "rgba(148,163,184,0.2)" },
    added:   { bg: "rgba(34,197,94,0.12)",   color: "#22c55e", border: "rgba(34,197,94,0.3)"   },
    removed: { bg: "rgba(239,68,68,0.1)",    color: "#ef4444", border: "rgba(239,68,68,0.25)"  },
    admin:   { bg: "rgba(251,191,36,0.12)",  color: "#fbbf24", border: "rgba(251,191,36,0.35)" },
  };
  const s = styles[variant];
  return (
    <span style={{
      display: "inline-block", padding: "1px 7px", borderRadius: 3, fontSize: 11,
      fontFamily: "var(--font-mono)", fontWeight: 600, margin: "1px 2px",
      background: s.bg, color: s.color, border: `1px solid ${s.border}`,
    }}>
      {role.replace("ROLE_", "")}
    </span>
  );
}

// ─── Timeline Node (Left Rail) ────────────────────────────────────────────────

function TimelineNode({
  item,
  isSelected,
  isLast,
  onClick,
}: {
  item: AuditTimelineItemDTO;
  isSelected: boolean;
  isLast: boolean;
  onClick: () => void;
}) {
  const { date, time } = formatTs(item.timestamp);
  const isCritical = item.accountLocked || !item.enabled;

  const dotColor = isSelected
    ? "#3b82f6"
    : item.hasAdminRoleEscalation
    ? "#fbbf24"
    : isCritical
    ? "#ef4444"
    : "#334155";

  return (
    <div onClick={onClick} style={{ position: "relative", paddingLeft: 28, cursor: "pointer" }}>
      {/* connector line */}
      {!isLast && (
        <div style={{
          position: "absolute", left: 7, top: 22, bottom: -8,
          width: 2, background: "linear-gradient(to bottom, #1e293b 60%, transparent)",
        }} />
      )}
      {/* dot */}
      <div style={{
        position: "absolute", left: 0, top: 16, width: 16, height: 16,
        borderRadius: "50%", background: dotColor, zIndex: 1,
        border: `2px solid ${dotColor}55`,
        boxShadow: isSelected ? `0 0 0 3px ${dotColor}30` : "none",
        transition: "all 0.15s",
      }} />

      {/* card */}
      <div style={{
        marginBottom: 6, padding: "11px 13px",
        background: isSelected ? "rgba(59,130,246,0.07)" : "rgba(15,23,42,0.55)",
        border: `1px solid ${
          isSelected      ? "#3b82f644"
          : isCritical    ? "#ef444430"
          : item.hasAdminRoleEscalation ? "#fbbf2430"
          : "#1e293b"
        }`,
        borderRadius: 8, transition: "all 0.15s",
      }}>
        {/* row 1: rev# + badge + flags */}
        <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 5 }}>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "#60a5fa", fontWeight: 700 }}>
            #{item.revisionNumber}
          </span>
          <RevBadge type={item.revisionType} />
          {isCritical && <span title="Critical account change">🚩</span>}
          {item.hasAdminRoleEscalation && <span title="Admin role escalation">👑</span>}
        </div>
        {/* row 2: date + time */}
        <div style={{ display: "flex", gap: 6, alignItems: "center", marginBottom: 5 }}>
          <span style={{ fontSize: 11, color: "#475569" }}>{date}</span>
          <span style={{ fontSize: 10, color: "#1e293b" }}>·</span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#64748b" }}>{time}</span>
        </div>
        {/* row 3: actor + IP */}
        <div style={{ display: "flex", alignItems: "center", gap: 5, marginBottom: 4 }}>
          <span style={{ fontSize: 11, color: "#475569" }}>by</span>
          <span style={{ fontSize: 12, color: "#cbd5e1", fontWeight: 600 }}>{item.changedBy}</span>
          <span style={{ fontSize: 10, color: "#1e293b" }}>·</span>
          <IPLabel ip={item.ipAddress} />
        </div>
        {/* row 4: email */}
        <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "#334155", marginTop: 2 }}>
          {item.email}
        </div>
      </div>
    </div>
  );
}

// ─── Diff Table (Right Rail) ──────────────────────────────────────────────────

function DiffTable({ diff, currentRevision }: { diff: AuditDiffDTO; currentRevision: number }) {
  const [showUnchanged, setShowUnchanged] = useState(false);

  const renderValue = (field: DiffField, isNew: boolean) => {
    const val = isNew ? field.currentValue : field.previousValue;

    if (field.fieldType === "ROLES") {
      const roles = val.split(",").map((r) => r.trim()).filter(Boolean);
      if (roles.length === 0) return <span style={{ color: "#334155", fontSize: 11 }}>none</span>;
      return (
        <>
          {roles.map((r) => {
            let variant: "neutral" | "added" | "removed" | "admin" = "neutral";
            if (isNew) {
              if (diff.addedRoles.includes(r))   variant = r === "ROLE_ADMIN" ? "admin" : "added";
            } else {
              if (diff.removedRoles.includes(r)) variant = "removed";
            }
            return <RolePill key={r} role={r} variant={variant} />;
          })}
        </>
      );
    }

    if (field.fieldType === "BOOLEAN") {
      const color = val === "true" ? "#22c55e" : val === "false" ? "#ef4444" : "#64748b";
      return (
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color, fontWeight: 600 }}>
          {val}
        </span>
      );
    }

    return <span style={{ fontSize: 12, color: "#cbd5e1" }}>{val || "—"}</span>;
  };

  const renderRow = (f: DiffField, isChanged: boolean) => (
    <tr key={f.fieldName} style={{
      background: f.critical && isChanged
        ? "rgba(239,68,68,0.05)"
        : f.fieldName === "roles" && isChanged && diff.adminEscalation
        ? "rgba(251,191,36,0.06)"
        : "transparent",
      borderBottom: "1px solid #0f172a",
    }}>
      <td style={{ padding: "8px 12px", color: "#64748b", fontSize: 11, whiteSpace: "nowrap", fontWeight: 600 }}>
        {f.critical && <span style={{ marginRight: 5, fontSize: 10 }}>⚡</span>}
        {f.fieldLabel}
      </td>
      <td style={{ padding: "8px 12px", color: "#475569" }}>
        {renderValue(f, false)}
      </td>
      <td style={{ padding: "8px 12px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
          {renderValue(f, true)}
          {isChanged && (
            <span style={{
              fontSize: 9, fontWeight: 700, letterSpacing: "0.06em",
              padding: "1px 5px", borderRadius: 3,
              background: "rgba(59,130,246,0.15)", color: "#60a5fa",
            }}>ΔCHANGED</span>
          )}
          {f.fieldName === "roles" && diff.adminEscalation && (
            <span style={{ fontSize: 11 }}>👑</span>
          )}
          {f.critical && isChanged && (
            <span style={{ fontSize: 11 }}>🚩</span>
          )}
        </div>
      </td>
    </tr>
  );

  return (
    <div>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, fontFamily: "var(--font-mono)" }}>
        <thead>
          <tr>
            {["Field", `Rev #${diff.previousRevisionNumber ?? "—"} (prev)`, `Rev #${currentRevision} (new)`].map((h) => (
              <th key={h} style={{
                textAlign: "left", padding: "8px 12px", fontSize: 10,
                color: "#334155", fontWeight: 700, letterSpacing: "0.1em",
                textTransform: "uppercase", borderBottom: "1px solid #1e293b",
              }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {diff.changedFields.map((f) => renderRow(f, true))}
          {showUnchanged && diff.unchangedFields.map((f) => renderRow(f, false))}
        </tbody>
      </table>
      {diff.unchangedFields.length > 0 && (
        <button
          onClick={() => setShowUnchanged((v) => !v)}
          style={{
            width: "100%", padding: "7px", background: "rgba(15,23,42,0.4)",
            border: "none", borderTop: "1px solid #0f172a",
            color: "#334155", fontSize: 11, cursor: "pointer",
            fontFamily: "var(--font-mono)",
          }}
        >
          {showUnchanged ? "▲ Hide" : "▼ Show"} {diff.unchangedFields.length} unchanged fields
        </button>
      )}
    </div>
  );
}

// ─── Inspector Panel (Right Rail) ─────────────────────────────────────────────

function Inspector({
  selectedItem,
}: {
  selectedItem: AuditTimelineItemDTO | null;
}) {
  const { data: detail, isLoading, isError } = useRevisionDetail(
    selectedItem?.userId,
    selectedItem?.revisionNumber
  );

  if (!selectedItem) {
    return (
      <div style={{
        height: "100%", display: "flex", flexDirection: "column",
        alignItems: "center", justifyContent: "center", gap: 12,
      }}>
        <div style={{ fontSize: 36 }}>🔍</div>
        <p style={{ fontSize: 12, color: "#334155", textAlign: "center", maxWidth: 180 }}>
          Select a revision from the timeline to inspect
        </p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ fontSize: 11, color: "#334155", fontFamily: "var(--font-mono)", letterSpacing: "0.1em" }}>
            LOADING REVISION #{selectedItem.revisionNumber}...
          </div>
          <div style={{
            marginTop: 12, width: 200, height: 2,
            background: "#0f172a", borderRadius: 2, overflow: "hidden",
          }}>
            <div style={{
              height: "100%", width: "40%",
              background: "linear-gradient(90deg, transparent, #3b82f6, transparent)",
              animation: "slide 1.2s ease-in-out infinite",
            }} />
          </div>
        </div>
      </div>
    );
  }

  if (isError || !detail) {
    return (
      <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <p style={{ fontSize: 12, color: "#ef4444" }}>Failed to load revision details.</p>
      </div>
    );
  }

  const { date, time } = formatTs(detail.timestamp);

  return (
    <div style={{ padding: 20, overflowY: "auto", height: "100%" }}>
      {/* Header */}
      <div style={{ marginBottom: 18 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 3 }}>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "#334155", letterSpacing: "0.12em", textTransform: "uppercase" }}>Revision</span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 22, fontWeight: 700, color: "#60a5fa" }}>
            #{detail.revisionNumber}
          </span>
          <RevBadge type={detail.revisionType} />
        </div>
        <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#475569" }}>
          {date} · {time}
        </div>
      </div>

      {/* Alert banners */}
      {detail.diff?.criticalChange && (
        <div style={{
          marginBottom: 14, padding: "9px 13px",
          background: "rgba(239,68,68,0.08)", border: "1px solid #ef444430",
          borderRadius: 7, display: "flex", gap: 8, alignItems: "flex-start",
        }}>
          <span>🚩</span>
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: "#ef4444" }}>Critical State Change</div>
            <div style={{ fontSize: 11, color: "#ef444477", marginTop: 2 }}>
              {detail.accountLocked && "Account is locked. "}
              {!detail.enabled && "Account is disabled."}
            </div>
          </div>
        </div>
      )}
      {detail.diff?.adminEscalation && (
        <div style={{
          marginBottom: 14, padding: "9px 13px",
          background: "rgba(251,191,36,0.08)", border: "1px solid #fbbf2430",
          borderRadius: 7, display: "flex", gap: 8, alignItems: "flex-start",
        }}>
          <span>👑</span>
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: "#fbbf24" }}>Admin Role Escalation</div>
            <div style={{ fontSize: 11, color: "#fbbf2477", marginTop: 2 }}>
              ROLE_ADMIN was granted in this revision.
            </div>
          </div>
        </div>
      )}

      {/* Identity card */}
      <div style={{
        background: "rgba(15,23,42,0.7)", border: "1px solid #1e293b",
        borderRadius: 8, padding: "13px 15px", marginBottom: 14,
      }}>
        <div style={{ fontSize: 10, fontWeight: 700, color: "#334155", letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 9 }}>
          Identity
        </div>
        {([
          ["User ID",    detail.userId,      true ],
          ["Username",   detail.username,    false],
          ["Email",      detail.email,       false],
          ["Sign-up",    detail.signUpMethod,true ],
        ] as [string, string | number | null, boolean][]).map(([label, value, mono]) => (
          <div key={label} style={{ display: "flex", gap: 8, marginBottom: 5, alignItems: "baseline" }}>
            <span style={{ fontSize: 11, color: "#334155", minWidth: 64 }}>{label}</span>
            <span style={{
              fontSize: 12, color: "#cbd5e1",
              fontFamily: mono ? "var(--font-mono)" : "inherit",
            }}>{value ?? "—"}</span>
          </div>
        ))}
        <div style={{ display: "flex", gap: 8, marginBottom: 5, alignItems: "center" }}>
          <span style={{ fontSize: 11, color: "#334155", minWidth: 64 }}>IP</span>
          <IPLabel ip={detail.ipAddress} />
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <span style={{ fontSize: 11, color: "#334155", minWidth: 64 }}>Actor</span>
          <span style={{ fontSize: 12, color: "#e2e8f0", fontWeight: 600 }}>{detail.changedBy}</span>
          {detail.diff?.previousChangedBy && (
            <span style={{ fontSize: 10, color: "#334155" }}>
              (prev by {detail.diff.previousChangedBy})
            </span>
          )}
        </div>
      </div>

      {/* Diff table */}
      <div style={{
        background: "rgba(15,23,42,0.7)", border: "1px solid #1e293b",
        borderRadius: 8, overflow: "hidden", marginBottom: 14,
      }}>
        <div style={{
          padding: "9px 13px", borderBottom: "1px solid #0f172a",
          display: "flex", alignItems: "center", justifyContent: "space-between",
        }}>
          <span style={{ fontSize: 10, fontWeight: 700, color: "#334155", letterSpacing: "0.12em", textTransform: "uppercase" }}>
            Δ Delta
          </span>
          {detail.diff && (
            <span style={{ fontSize: 10, color: "#475569", fontFamily: "var(--font-mono)" }}>
              {detail.diff.changedFields.length} field{detail.diff.changedFields.length !== 1 ? "s" : ""} changed
            </span>
          )}
        </div>
        {detail.diff ? (
          <DiffTable diff={detail.diff} currentRevision={detail.revisionNumber} />
        ) : (
          <div style={{ padding: "20px 16px", fontSize: 12, color: "#334155", textAlign: "center" }}>
            First revision — no previous state to compare.
          </div>
        )}
      </div>

      {/* Current roles */}
      <div style={{
        background: "rgba(15,23,42,0.7)", border: "1px solid #1e293b",
        borderRadius: 8, padding: "13px 15px",
      }}>
        <div style={{ fontSize: 10, fontWeight: 700, color: "#334155", letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 8 }}>
          Current Roles
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 2 }}>
          {detail.roles.length > 0
            ? detail.roles.map((r) => (
                <RolePill key={r} role={r} variant={r === "ROLE_ADMIN" ? "admin" : "neutral"} />
              ))
            : <span style={{ fontSize: 12, color: "#334155" }}>No roles assigned</span>
          }
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN PAGE
// ─────────────────────────────────────────────────────────────────────────────

export default function AuditUsersPage() {
  const [filter, setFilter] = useState<AuditFilterRequest>({
    page: 0,
    size: PAGE_SIZE,
  });
  const [selectedItem, setSelectedItem] = useState<AuditTimelineItemDTO | null>(null);

  // Debounced filter update for text inputs
  const updateFilter = useCallback((patch: Partial<AuditFilterRequest>) => {
    setFilter((prev) => ({ ...prev, ...patch, page: 0 }));
    setSelectedItem(null);
  }, []);

  const { data: pageData, isLoading, isFetching } = useTimelineItems(filter);

  const items = pageData?.content ?? [];
  const totalElements = pageData?.totalElements ?? 0;
  const totalPages    = pageData?.totalPages    ?? 0;

  // Stats from current page (in real app these might come from a separate summary endpoint)
  const stats = useMemo(() => ({
    total:       totalElements,
    critical:    items.filter((i) => i.accountLocked || !i.enabled).length,
    escalations: items.filter((i) => i.hasAdminRoleEscalation).length,
    unknown:     items.filter((i) => !isKnownIP(i.ipAddress)).length,
  }), [items, totalElements]);

  const activeRevTypes: string[] = useMemo(
    () => filter.revisionTypes ? filter.revisionTypes.split(",").filter(Boolean) : [],
    [filter.revisionTypes]
  );

  const toggleRevType = (type: string) => {
    const active = activeRevTypes.includes(type)
      ? activeRevTypes.filter((t) => t !== type)
      : [...activeRevTypes, type];
    updateFilter({ revisionTypes: active.join(",") });
  };

  const clearFilters = () => {
    setFilter({ page: 0, size: PAGE_SIZE });
    setSelectedItem(null);
  };

  const hasActiveFilters = !!(filter.email || filter.changedBy || filter.ipAddress || filter.revisionTypes);

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=Epilogue:wght@400;500;600;700;800&display=swap');
        :root {
          --font-body: 'Epilogue', sans-serif;
          --font-mono: 'IBM Plex Mono', monospace;
          --bg-base:   #020817;
          --bg-surface: rgba(15,23,42,0.7);
          --border:    #0f172a;
          --border-mid: #1e293b;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        html, body { background: var(--bg-base); height: 100%; overflow: hidden; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 2px; }
        input { outline: none; }
        input::placeholder { color: #1e293b; }
        button { cursor: pointer; }
        @keyframes slide {
          0%   { transform: translateX(-100%); }
          100% { transform: translateX(350%); }
        }
        @keyframes pulseRed {
          0%, 100% { box-shadow: 0 0 0 0 rgba(239,68,68,0.3); }
          50%       { box-shadow: 0 0 0 5px transparent; }
        }
        .node-card:hover { opacity: 0.88; }
      `}</style>

      <div style={{
        height: "100vh", display: "flex", flexDirection: "column",
        fontFamily: "var(--font-body)", color: "#e2e8f0", background: "var(--bg-base)",
        overflow: "hidden",
      }}>

        {/* ── Top bar ─────────────────────────────────────────────────────── */}
        <div style={{
          display: "flex", alignItems: "center", gap: 14,
          padding: "12px 24px", borderBottom: "1px solid var(--border)",
          background: "rgba(2,8,23,0.95)", backdropFilter: "blur(12px)",
          flexShrink: 0,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
            <div style={{
              width: 30, height: 30, borderRadius: 7,
              background: "linear-gradient(135deg, #1d4ed8 0%, #3b82f6 100%)",
              display: "flex", alignItems: "center", justifyContent: "center", fontSize: 15,
            }}>🛡</div>
            <div>
              <div style={{ fontSize: 14, fontWeight: 800, color: "#f1f5f9", letterSpacing: "-0.02em" }}>
                Guardian Stack
              </div>
              <div style={{ fontSize: 9, color: "#334155", letterSpacing: "0.12em", textTransform: "uppercase" }}>
                Forensic Audit Console
              </div>
            </div>
          </div>

          <div style={{
            padding: "3px 9px", borderRadius: 20,
            background: "rgba(239,68,68,0.08)", border: "1px solid #ef444430",
            fontSize: 10, color: "#ef4444", fontWeight: 700, letterSpacing: "0.1em",
          }}>
            MASTER ADMIN · MFA VERIFIED
          </div>

          {isFetching && !isLoading && (
            <div style={{ fontSize: 10, color: "#334155", fontFamily: "var(--font-mono)", letterSpacing: "0.08em" }}>
              ↻ refreshing…
            </div>
          )}

          <div style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 10, color: "#1e293b" }}>
            /master-admin/audit/users
          </div>
        </div>

        {/* ── Stats strip ─────────────────────────────────────────────────── */}
        <div style={{
          display: "flex", borderBottom: "1px solid var(--border)",
          background: "rgba(2,8,23,0.5)", flexShrink: 0,
        }}>
          {([
            { label: "Total Events",      value: stats.total,       color: "#60a5fa", pulse: false },
            { label: "Critical Changes",  value: stats.critical,    color: "#ef4444", pulse: stats.critical > 0 },
            { label: "Admin Escalations", value: stats.escalations, color: "#fbbf24", pulse: false },
            { label: "Unknown IPs",       value: stats.unknown,     color: "#f97316", pulse: false },
          ] as const).map((s, i) => (
            <div key={s.label} style={{
              flex: 1, padding: "10px 20px",
              borderRight: i < 3 ? "1px solid var(--border)" : "none",
              display: "flex", alignItems: "center", gap: 10,
            }}>
              <div style={{
                width: 34, height: 34, borderRadius: 7, flexShrink: 0,
                background: `${s.color}12`, border: `1px solid ${s.color}30`,
                display: "flex", alignItems: "center", justifyContent: "center",
                fontFamily: "var(--font-mono)", fontSize: 15, fontWeight: 700, color: s.color,
                ...(s.pulse ? { animation: "pulseRed 2s infinite" } : {}),
              }}>{s.value}</div>
              <span style={{ fontSize: 11, color: "#334155" }}>{s.label}</span>
            </div>
          ))}
        </div>

        {/* ── Filter bar ──────────────────────────────────────────────────── */}
        <div style={{
          display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap",
          padding: "10px 24px", borderBottom: "1px solid var(--border)",
          background: "rgba(2,8,23,0.6)", flexShrink: 0,
        }}>
          <span style={{ fontSize: 9, color: "#1e293b", fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", marginRight: 2 }}>
            FILTER
          </span>
          {([
            { key: "email",      placeholder: "Email / User ID", width: 180 },
            { key: "changedBy",  placeholder: "Actor (changedBy)", width: 160 },
            { key: "ipAddress",  placeholder: "IP or prefix", width: 130 },
          ] as const).map(({ key, placeholder, width }) => (
            <input
              key={key}
              value={(filter as Record<string, string>)[key] ?? ""}
              onChange={(e) => updateFilter({ [key]: e.target.value || undefined })}
              placeholder={placeholder}
              style={{
                width, height: 30, padding: "0 10px",
                background: "rgba(15,23,42,0.8)", border: "1px solid var(--border-mid)",
                borderRadius: 5, color: "#cbd5e1", fontSize: 12,
                fontFamily: "var(--font-body)",
              }}
            />
          ))}

          {/* Rev type toggles */}
          {(["CREATED", "MODIFIED", "DELETED"] as const).map((type) => {
            const cfg = REV_CFG[type];
            const active = activeRevTypes.includes(type);
            return (
              <button
                key={type}
                onClick={() => toggleRevType(type)}
                style={{
                  height: 30, padding: "0 10px", borderRadius: 5,
                  border: `1px solid ${active ? cfg.color : "#1e293b"}`,
                  background: active ? cfg.bg : "rgba(15,23,42,0.8)",
                  color: active ? cfg.color : "#334155",
                  fontSize: 11, fontWeight: 700, fontFamily: "var(--font-mono)",
                  letterSpacing: "0.05em", transition: "all 0.12s",
                }}
              >
                {cfg.icon} {type}
              </button>
            );
          })}

          {hasActiveFilters && (
            <button
              onClick={clearFilters}
              style={{
                height: 30, padding: "0 10px", borderRadius: 5,
                border: "1px solid #1e293b", background: "transparent",
                color: "#475569", fontSize: 11, fontFamily: "var(--font-body)",
              }}
            >
              ✕ Clear
            </button>
          )}

          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "#1e293b" }}>
              {totalElements.toLocaleString()} events
            </span>
            {/* Pagination */}
            {totalPages > 1 && (
              <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                <button
                  onClick={() => setFilter((f) => ({ ...f, page: f.page - 1 }))}
                  disabled={filter.page === 0}
                  style={{
                    height: 26, padding: "0 8px", borderRadius: 4,
                    border: "1px solid #1e293b", background: "transparent",
                    color: filter.page === 0 ? "#1e293b" : "#64748b",
                    fontSize: 11, fontFamily: "var(--font-mono)",
                  }}
                >←</button>
                <span style={{ fontSize: 10, color: "#334155", fontFamily: "var(--font-mono)" }}>
                  {filter.page + 1} / {totalPages}
                </span>
                <button
                  onClick={() => setFilter((f) => ({ ...f, page: f.page + 1 }))}
                  disabled={filter.page >= totalPages - 1}
                  style={{
                    height: 26, padding: "0 8px", borderRadius: 4,
                    border: "1px solid #1e293b", background: "transparent",
                    color: filter.page >= totalPages - 1 ? "#1e293b" : "#64748b",
                    fontSize: 11, fontFamily: "var(--font-mono)",
                  }}
                >→</button>
              </div>
            )}
          </div>
        </div>

        {/* ── Main body ───────────────────────────────────────────────────── */}
        <div style={{ display: "flex", flex: 1, overflow: "hidden", minHeight: 0 }}>

          {/* LEFT RAIL — Timeline */}
          <div style={{
            width: "60%", overflowY: "auto",
            padding: "18px 16px 18px 24px",
            borderRight: "1px solid var(--border)",
          }}>
            {isLoading ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 8, paddingTop: 8 }}>
                {Array.from({ length: 8 }).map((_, i) => (
                  <div key={i} style={{
                    height: 88, borderRadius: 8, marginLeft: 28,
                    background: "rgba(15,23,42,0.4)", border: "1px solid #0f172a",
                    opacity: 1 - i * 0.1,
                  }} />
                ))}
              </div>
            ) : items.length === 0 ? (
              <div style={{ textAlign: "center", paddingTop: 60 }}>
                <div style={{ fontSize: 32, marginBottom: 10 }}>📭</div>
                <div style={{ fontSize: 13, color: "#334155" }}>No audit events match your filters.</div>
              </div>
            ) : (
              <>
                {/* User group headers */}
                {items.reduce<{ userId: number | null; nodes: React.ReactNode[] }>(
                  (acc, item, i) => {
                    const newUser = item.userId !== acc.userId;
                    if (newUser) {
                      acc.userId = item.userId;
                      acc.nodes.push(
                        <div key={`header-${item.userId}`} style={{
                          marginBottom: 8, marginLeft: 28,
                          paddingBottom: 5, borderBottom: "1px solid #0f172a",
                        }}>
                          <span style={{ fontSize: 9, color: "#1e293b", fontWeight: 700, letterSpacing: "0.12em", textTransform: "uppercase" }}>
                            User · {item.email}
                          </span>
                        </div>
                      );
                    }
                    acc.nodes.push(
                      <div key={item.revisionNumber} className="node-card">
                        <TimelineNode
                          item={item}
                          isSelected={selectedItem?.revisionNumber === item.revisionNumber}
                          isLast={i === items.length - 1 || items[i + 1]?.userId !== item.userId}
                          onClick={() =>
                            setSelectedItem(
                              selectedItem?.revisionNumber === item.revisionNumber ? null : item
                            )
                          }
                        />
                      </div>
                    );
                    return acc;
                  },
                  { userId: null, nodes: [] }
                ).nodes}
              </>
            )}
          </div>

          {/* RIGHT RAIL — Inspector */}
          <div style={{ width: "40%", overflowY: "auto", background: "rgba(2,8,23,0.3)" }}>
            <Inspector selectedItem={selectedItem} />
          </div>
        </div>
      </div>
    </>
  );
}