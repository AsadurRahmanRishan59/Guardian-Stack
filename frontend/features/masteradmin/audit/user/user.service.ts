// features/masteradmin/audit/user/user.service.ts
import { api } from "@/lib/api.client";
import { ApiResponse } from "@/types/api.types";
import { AuditFilterRequest, AuditTimelineItemDTO, MasterAdminUserAuditDTO } from "./user.types";

/**
 * LEFT PANEL
 * Slim timeline items — paginated, filterable.
 * Call this on page load and whenever filters/page change.
 */
export function getTimelineItems(
  filter: AuditFilterRequest
): Promise<ApiResponse<AuditTimelineItemDTO>> {
  return api.client.get(
    '/master-admin/audit/users',
    filter as Record<string, string | number | boolean | null | undefined>
  );
}

/**
 * SINGLE USER TIMELINE
 * All timeline nodes for one user.
 * Call when Admin opens the user-specific drill-down.
 */
export function getUserTimeline(
  userId: number
): Promise<ApiResponse<AuditTimelineItemDTO[]>> {
  return api.client.get(`/master-admin/audit/users/${userId}`);
}

/**
 * RIGHT PANEL
 * Full revision detail with pre-computed diff.
 * Call lazily when Admin clicks a timeline node.
 */
export function getRevisionDetail(
  userId: number,
  revisionNumber: number
): Promise<ApiResponse<MasterAdminUserAuditDTO>> {
  return api.client.get(
    `/master-admin/audit/users/${userId}/revision/${revisionNumber}`
  );
}


// export function getAuditHistory(searchCriteria?: AuditFilterRequest): Promise<ApiResponse<MasterAdminUserAuditDTO>> {
//   return api.client.get('/master-admin/audit/users', searchCriteria as Record<string, string | number | boolean | null | undefined>);
// }

// export function getUserAuditHistory(userId: number): Promise<ApiResponse<MasterAdminUserAuditDTO>> {
//   return api.client.get(`/master-admin/audit/users/${userId}`);
// }

// export function getRevisionSnapshot(userId: number, revisionNumber: number): Promise<ApiResponse<MasterAdminUserAuditDTO>> {
//   return api.client.get(`/master-admin/audit/users/${userId}/revision/${revisionNumber}`);
// }