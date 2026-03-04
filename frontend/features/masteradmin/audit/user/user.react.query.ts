// features/masteradmin/audit/user/user.react.query.ts
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import type { AuditFilterRequest } from "./user.types";
import { getRevisionDetail, getTimelineItems, getUserTimeline } from "./user.service";

// ─── Query Keys ──────────────────────────────────────────────────────────────

export const auditKeys = {
  all:      ()                            => ["userAudit"]                        as const,
  timeline: (filter: AuditFilterRequest)  => ["userAudit", "timeline", filter]    as const,
  user:     (userId: number)              => ["userAudit", "user",     userId]     as const,
  detail:   (userId: number, rev: number) => ["userAudit", "detail",   userId, rev] as const,
};

// ─── LEFT PANEL ──────────────────────────────────────────────────────────────
// data shape: ApiResponse<AuditTimelineItemDTO[]>
//   → items        = response.data        (AuditTimelineItemDTO[])
//   → totalElements= response.pagination?.totalElements
//   → totalPages   = response.pagination?.totalPages

export function useTimelineItems(filter: AuditFilterRequest) {
  return useQuery({
    queryKey:        auditKeys.timeline(filter),
    queryFn:         () => getTimelineItems(filter),
    placeholderData: keepPreviousData,
    staleTime:       30_000,
  });
}

// ─── SINGLE USER DRILL-DOWN ───────────────────────────────────────────────────

export function useUserTimeline(userId?: number) {
  return useQuery({
    queryKey:  auditKeys.user(userId!),
    queryFn:   () => getUserTimeline(userId!),
    enabled:   !!userId,
    staleTime: 30_000,
  });
}

// ─── RIGHT PANEL ─────────────────────────────────────────────────────────────
// data shape: ApiResponse<MasterAdminUserAuditDTO>
//   → detail = response.data   (MasterAdminUserAuditDTO)
//
// staleTime: Infinity — forensic records are immutable, never re-fetch.
// gcTime: 10 min — keep cached for fast back-and-forth between nodes.

export function useRevisionDetail(userId?: number, revisionNumber?: number) {
  return useQuery({
    queryKey:  auditKeys.detail(userId!, revisionNumber!),
    queryFn:   () => getRevisionDetail(userId!, revisionNumber!),
    enabled:   !!userId && !!revisionNumber,
    staleTime: Infinity,
    gcTime:    10 * 60 * 1000,
  });
}