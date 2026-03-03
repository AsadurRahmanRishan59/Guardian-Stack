// features/masteradmin/audit/user/user.react.query.ts
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { AuditFilterRequest } from "./user.types";
import { getRevisionDetail, getTimelineItems, getUserTimeline } from "./user.service";

// ─── Query Keys (typed, factory pattern) ──────────────────────────────────

export const auditKeys = {
  all:      ()                                    => ['userAudit']                                           as const,
  timeline: (filter: AuditFilterRequest)          => ['userAudit', 'timeline', filter]                       as const,
  user:     (userId: number)                      => ['userAudit', 'user',     userId]                       as const,
  detail:   (userId: number, rev: number)         => ['userAudit', 'detail',   userId, rev]                  as const,
};

// ─────────────────────────────────────────────────────────────────────────────
// LEFT PANEL
// Slim timeline items — driven by filter state.
// placeholderData keeps the previous page visible during pagination transitions.
// ─────────────────────────────────────────────────────────────────────────────

export function useTimelineItems(filter: AuditFilterRequest) {
  return useQuery({
    queryKey:        auditKeys.timeline(filter),
    queryFn:         () => getTimelineItems(filter),
    placeholderData: keepPreviousData,  // smooth page transitions
    staleTime:       30_000,            // 30s — audit data is near-real-time, not live
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// SINGLE USER DRILL-DOWN
// Full timeline for one user. Only fetches when userId is provided.
// ─────────────────────────────────────────────────────────────────────────────

export function useUserTimeline(userId?: number) {
  return useQuery({
    queryKey: auditKeys.user(userId!),
    queryFn:  () => getUserTimeline(userId!),
    enabled:  !!userId,
    staleTime: 30_000,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// RIGHT PANEL
// Full revision detail + diff. Loaded lazily on node click.
//
// staleTime: Infinity — forensic data is immutable; once fetched, never re-fetch.
// gcTime: 10 min — keep in cache for fast back-and-forth between nodes.
// ─────────────────────────────────────────────────────────────────────────────

export function useRevisionDetail(userId?: number, revisionNumber?: number) {
  return useQuery({
    queryKey: auditKeys.detail(userId!, revisionNumber!),
    queryFn:  () => getRevisionDetail(userId!, revisionNumber!),
    enabled:  !!userId && !!revisionNumber,
    staleTime: Infinity,
    gcTime:    10 * 60 * 1000,
  });
}


// export function useQueryUserAuditHistory(searchCriteria: AuditFilterRequest) {
//     return useQuery({
//         // Include searchCriteria in queryKey so changes trigger a reload
//         queryKey: ['userAudit', 'global', searchCriteria], 
//         queryFn: async () => {
//             const response = await getAuditHistory(searchCriteria);
//             return response ?? null;
//         },
//         placeholderData: (previousData) => previousData, // Smooth transitions during pagination
//         staleTime: 30000, // 30 seconds
//     });
// }

// export function useQueryUserTimeline(userId?: number) {
//     return useQuery({
//         queryKey: ["userAudit", "timeline", userId],
//         queryFn: async () => {
//             if (!userId) return null;
//             const response = await getUserAuditHistory(userId);
//             return response?.data || [];
//         },
//         enabled: !!userId, // Won't run until userId is provided
//     });
// }

// /**
//  * Hook to fetch a single, specific revision snapshot.
//  * Used when the Admin clicks a "node" in the timeline to see full details.
//  */
// export function useQueryRevisionSnapshot(userId?: number, revisionNumber?: number) {
//     return useQuery({
//         // Unique key per user and revision to ensure correct caching
//         queryKey: ["userAudit", "snapshot", userId, revisionNumber],
        
//         queryFn: async () => {
//             if (!userId || !revisionNumber) return null;
//             const response = await getRevisionSnapshot(userId, revisionNumber);
//             return response?.data || null;
//         },

//         // Only run the query if we actually have both IDs
//         enabled: !!userId && !!revisionNumber,

//         // Forensic data doesn't change, so we can cache it indefinitely
//         staleTime: Infinity, 
//         gcTime: 10 * 60 * 1000, // Keep in memory for 10 minutes of inactivity
//     });
// }