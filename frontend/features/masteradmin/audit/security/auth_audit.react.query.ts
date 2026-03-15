// features/masteradmin/audit/security/auth_audit.react.query.ts
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import type { AuthAuditFilterRequest } from "./auth_audit.types";
import { getAuthAuditTimelineItems } from "./auth_audit.service";

// ─── Query Keys ───────────────────────────────────────────────────────────────

export const securityAuditKeys = {
  all:      ()                               => ["securityAudit"]                       as const,
  timeline: (filter: AuthAuditFilterRequest) => ["securityAudit", "timeline", filter]  as const,
};

// ─── LEFT PANEL ───────────────────────────────────────────────────────────────
// data shape: ApiResponse<AuthAuditTimelineItemDTO[]>
//   → items         = response.data
//   → totalElements = response.pagination?.totalElements
//   → totalPages    = response.pagination?.totalPages

export function useAuthAuditTimelineItems(filter: AuthAuditFilterRequest) {
  return useQuery({
    queryKey:        securityAuditKeys.timeline(filter),
    queryFn:         () => getAuthAuditTimelineItems(filter),
    placeholderData: keepPreviousData,
    staleTime:       30_000,   // 30 s — security log is near-realtime but not live
  });
}