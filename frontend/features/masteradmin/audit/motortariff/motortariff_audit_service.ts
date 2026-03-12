// features/masteradmin/audit/motortariff/motortariff_audit_service.ts
import { api } from "@/lib/api.client";
import type { ApiResponse } from "@/types/api.types";
import type {
  MotorTariffAuditFilterRequest,
  MotorTariffAuditTimelineItemDTO,
  MotorTariffAuditDTO,
} from "./motortariff_audit_types";

/**
 * Converts MotorTariffAuditFilterRequest → URLSearchParams.
 *
 * Spring's @RequestParam Set<String> revisionTypes expects REPEATED params:
 *   ✅  ?revisionTypes=CREATED&revisionTypes=MODIFIED
 *   ❌  ?revisionTypes=CREATED,MODIFIED
 */
function buildParams(filter: MotorTariffAuditFilterRequest): URLSearchParams {
  const p = new URLSearchParams();

  if (filter.tariffKey  != null) p.set("tariffKey",  String(filter.tariffKey));
  if (filter.tariffType)         p.set("tariffType",  filter.tariffType);
  if (filter.changedBy)          p.set("changedBy",   filter.changedBy);
  if (filter.ipAddress)          p.set("ipAddress",   filter.ipAddress);
  if (filter.from)               p.set("from",        filter.from);
  if (filter.to)                 p.set("to",          filter.to);
  if (filter.page != null)       p.set("page",        String(filter.page));
  if (filter.size != null)       p.set("size",        String(filter.size));

  if (filter.revisionTypes) {
    filter.revisionTypes
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean)
      .forEach((type) => p.append("revisionTypes", type));
  }

  return p;
}

/** LEFT PANEL — paginated timeline items. */
export function getMotorTariffTimelineItems(
  filter: MotorTariffAuditFilterRequest
): Promise<ApiResponse<MotorTariffAuditTimelineItemDTO[]>> {
  return api.client.get(
    `/master-admin/audit/tariffs/motor?${buildParams(filter).toString()}`
  );
}

/** SINGLE TARIFF DRILL-DOWN — all revisions for one tariff entry. */
export function getMotorTariffTimeline(
  tariffKey: number
): Promise<ApiResponse<MotorTariffAuditTimelineItemDTO[]>> {
  return api.client.get(`/master-admin/audit/tariffs/motor/${tariffKey}`);
}

/** RIGHT PANEL — full revision detail + pre-computed diff. */
export function getMotorTariffRevisionDetail(
  tariffKey: number,
  revisionNumber: number
): Promise<ApiResponse<MotorTariffAuditDTO>> {
  return api.client.get(
    `/master-admin/audit/tariffs/motor/${tariffKey}/revision/${revisionNumber}`
  );
}