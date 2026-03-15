// features/masteradmin/audit/security/auth_audit.service.ts
import { api } from "@/lib/api.client";
import type { ApiResponse } from "@/types/api.types";
import type {
  AuthAuditFilterRequest,
  AuthAuditTimelineItemDTO,
} from "./auth_audit.types";

function buildParams(filter: AuthAuditFilterRequest): URLSearchParams {
  const p = new URLSearchParams();

  if (filter.eventType)       p.set("eventType",  filter.eventType);
  if (filter.userEmail)       p.set("userEmail",  filter.userEmail);
  if (filter.ipAddress)       p.set("ipAddress",  filter.ipAddress);
  if (filter.requestId)       p.set("requestId",  filter.requestId);
  if (filter.success != null) p.set("success",    String(filter.success));
  if (filter.from)            p.set("from",       filter.from);
  if (filter.to)              p.set("to",         filter.to);
  if (filter.page != null)    p.set("page",       String(filter.page));
  if (filter.size != null)    p.set("size",       String(filter.size));

  return p;
}

export function getAuthAuditTimelineItems(
  filter: AuthAuditFilterRequest
): Promise<ApiResponse<AuthAuditTimelineItemDTO[]>> {
  return api.client.get(
    `/master-admin/audit/security?${buildParams(filter).toString()}`
  );
}