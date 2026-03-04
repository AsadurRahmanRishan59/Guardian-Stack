// features/masteradmin/audit/user/user.service.ts
import { api } from "@/lib/api.client";
import type { ApiResponse } from "@/types/api.types";
import type {
  AuditFilterRequest,
  AuditTimelineItemDTO,
  MasterAdminUserAuditDTO,
} from "./user.types";

/**
 * Converts AuditFilterRequest → URLSearchParams.
 *
 * Spring's @RequestParam Set<String> revisionTypes expects REPEATED params:
 *   ✅  ?revisionTypes=CREATED&revisionTypes=MODIFIED
 *   ❌  ?revisionTypes=CREATED,MODIFIED
 *
 * URLSearchParams.append() handles the repeated-key case correctly.
 */
function buildParams(filter: AuditFilterRequest): URLSearchParams {
  const p = new URLSearchParams();

  if (filter.userId    != null) p.set("userId",    String(filter.userId));
  if (filter.email)             p.set("email",     filter.email);
  if (filter.changedBy)         p.set("changedBy", filter.changedBy);
  if (filter.ipAddress)         p.set("ipAddress", filter.ipAddress);
  if (filter.from)              p.set("from",      filter.from);
  if (filter.to)                p.set("to",        filter.to);
  if (filter.page != null)      p.set("page",      String(filter.page));
  if (filter.size != null)      p.set("size",      String(filter.size));

  // Split "CREATED,MODIFIED" → ?revisionTypes=CREATED&revisionTypes=MODIFIED
  if (filter.revisionTypes) {
    filter.revisionTypes
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean)
      .forEach((type) => p.append("revisionTypes", type));
  }

  return p;
}

/** LEFT PANEL — paginated timeline items. pagination field will be present. */
export function getTimelineItems(
  filter: AuditFilterRequest
): Promise<ApiResponse<AuditTimelineItemDTO[]>> {
  return api.client.get(
    `/master-admin/audit/users?${buildParams(filter).toString()}`
  );
}

/** SINGLE USER DRILL-DOWN — all revisions for one user. */
export function getUserTimeline(
  userId: number
): Promise<ApiResponse<AuditTimelineItemDTO[]>> {
  return api.client.get(`/master-admin/audit/users/${userId}`);
}

/** RIGHT PANEL — full revision detail + pre-computed diff. */
export function getRevisionDetail(
  userId: number,
  revisionNumber: number
): Promise<ApiResponse<MasterAdminUserAuditDTO>> {
  return api.client.get(
    `/master-admin/audit/users/${userId}/revision/${revisionNumber}`
  );
}