// features/masteradmin/audit/user/user.react.query.ts

import { useQuery } from "@tanstack/react-query";
import { AuditFilterRequest } from "./user.types";
import { getAuditHistory, getRevisionSnapshot, getUserAuditHistory } from "./user.service";


// features/masteradmin/audit/user/user.react.query.ts

export function useQueryUserAuditHistory(searchCriteria: AuditFilterRequest) {
    return useQuery({
        // Include searchCriteria in queryKey so changes trigger a reload
        queryKey: ['userAudit', 'global', searchCriteria], 
        queryFn: async () => {
            const response = await getAuditHistory(searchCriteria);
            return response ?? null;
        },
        placeholderData: (previousData) => previousData, // Smooth transitions during pagination
        staleTime: 30000, // 30 seconds
    });
}

export function useQueryUserTimeline(userId?: number) {
    return useQuery({
        queryKey: ["userAudit", "timeline", userId],
        queryFn: async () => {
            if (!userId) return null;
            const response = await getUserAuditHistory(userId);
            return response?.data || [];
        },
        enabled: !!userId, // Won't run until userId is provided
    });
}


// features/masteradmin/audit/user/user.react.query.ts

/**
 * Hook to fetch a single, specific revision snapshot.
 * Used when the Admin clicks a "node" in the timeline to see full details.
 */
export function useQueryRevisionSnapshot(userId?: number, revisionNumber?: number) {
    return useQuery({
        // Unique key per user and revision to ensure correct caching
        queryKey: ["userAudit", "snapshot", userId, revisionNumber],
        
        queryFn: async () => {
            if (!userId || !revisionNumber) return null;
            const response = await getRevisionSnapshot(userId, revisionNumber);
            return response?.data || null;
        },

        // Only run the query if we actually have both IDs
        enabled: !!userId && !!revisionNumber,

        // Forensic data doesn't change, so we can cache it indefinitely
        staleTime: Infinity, 
        gcTime: 10 * 60 * 1000, // Keep in memory for 10 minutes of inactivity
    });
}