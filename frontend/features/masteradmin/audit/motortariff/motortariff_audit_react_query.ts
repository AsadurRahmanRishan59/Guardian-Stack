// features/masteradmin/audit/motortariff/motortariff_audit_react_query.ts
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import type { MotorTariffAuditFilterRequest } from "./motortariff_audit_types";
import {
  getMotorTariffTimelineItems,
  getMotorTariffTimeline,
  getMotorTariffRevisionDetail,
} from "./motortariff_audit_service";

// ─── Query Keys ──────────────────────────────────────────────────────────────

export const motorTariffAuditKeys = {
  all:      ()                                   => ["motorTariffAudit"]                              as const,
  timeline: (filter: MotorTariffAuditFilterRequest) => ["motorTariffAudit", "timeline", filter]      as const,
  tariff:   (tariffKey: number)                  => ["motorTariffAudit", "tariff",   tariffKey]       as const,
  detail:   (tariffKey: number, rev: number)     => ["motorTariffAudit", "detail",   tariffKey, rev]  as const,
};

// ─── LEFT PANEL ──────────────────────────────────────────────────────────────

export function useMotorTariffTimelineItems(filter: MotorTariffAuditFilterRequest) {
  return useQuery({
    queryKey:        motorTariffAuditKeys.timeline(filter),
    queryFn:         () => getMotorTariffTimelineItems(filter),
    placeholderData: keepPreviousData,
    staleTime:       30_000,
  });
}

// ─── SINGLE TARIFF DRILL-DOWN ─────────────────────────────────────────────────

export function useMotorTariffTimeline(tariffKey?: number) {
  return useQuery({
    queryKey:  motorTariffAuditKeys.tariff(tariffKey!),
    queryFn:   () => getMotorTariffTimeline(tariffKey!),
    enabled:   !!tariffKey,
    staleTime: 30_000,
  });
}

// ─── RIGHT PANEL ─────────────────────────────────────────────────────────────
// staleTime: Infinity — forensic records are immutable, never re-fetch.
// gcTime: 10 min — keep cached for fast back-and-forth between nodes.

export function useMotorTariffRevisionDetail(tariffKey?: number, revisionNumber?: number) {
  return useQuery({
    queryKey:  motorTariffAuditKeys.detail(tariffKey!, revisionNumber!),
    queryFn:   () => getMotorTariffRevisionDetail(tariffKey!, revisionNumber!),
    enabled:   !!tariffKey && !!revisionNumber,
    staleTime: Infinity,
    gcTime:    10 * 60 * 1000,
  });
}