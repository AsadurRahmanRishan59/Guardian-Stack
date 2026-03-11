// features/masteradmin/tariff/motor/motor_tariff_react_query.ts
import { useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import {
  getMotorTariffs,
  getMotorTariffById,
  createMotorTariff,
  updateMotorTariff,
  deleteMotorTariff,
  getMotorHierarchy,
} from "./motor.tariff.service";
import type { MotorTariffDTO, MotorTariffSearchCriteria } from "./motor.tariff.types";

// ── Query keys ────────────────────────────────────────────────────────────────
export const motorTariffKeys = {
  all: () => ["motorTariffs"] as const,
  list: (criteria: MotorTariffSearchCriteria) =>
    ["motorTariffs", "list", criteria] as const,
  detail: (key: number) => ["motorTariffs", "detail", key] as const,
  hierarchy: (level: string, params: Record<string, string | undefined>) =>
    ["motorTariffs", "hierarchy", level, params] as const,
};

// ── Paginated list ────────────────────────────────────────────────────────────
export function useMotorTariffs(criteria?: MotorTariffSearchCriteria) {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: motorTariffKeys.list(criteria ?? {}),
    queryFn: () => getMotorTariffs(criteria),
    staleTime: 2 * 60 * 1000,
    refetchOnWindowFocus: false,
  });

  return {
    motorTariffs: data?.data ?? [],
    pagination: {
      currentPage: data?.pagination?.currentPage ?? 0,
      pageSize: data?.pagination?.pageSize ?? 10,
      totalElements: data?.pagination?.totalElements ?? 0,
      totalPages: data?.pagination?.totalPages ?? 0,
      hasNext: data?.pagination?.hasNext ?? false,
      hasPrevious: data?.pagination?.hasPrevious ?? false,
      sortBy: data?.pagination?.sortBy ?? "tariffKey",
      sortDirection: data?.pagination?.sortDirection ?? "asc",
    },
    isLoading,
    error,
    refetch,
  };
}

// ── Single tariff (full DTO) ──────────────────────────────────────────────────
export function useMotorTariffById(tariffKey?: number) {
  const { data, isLoading, error } = useQuery({
    queryKey: motorTariffKeys.detail(tariffKey!),
    queryFn: async () => {
      const res = await getMotorTariffById(tariffKey!);
      return res.data ?? null;
    },
    enabled: !!tariffKey,
    staleTime: 0,
  });

  return { data, isLoading, error };
}

// ── Create ────────────────────────────────────────────────────────────────────
export function useCreateMotorTariff() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (dto: MotorTariffDTO) => createMotorTariff(dto),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: motorTariffKeys.all() });
      toast.success(res?.message ?? "Motor tariff created successfully.");
    },
    onError: (err: { message?: string }) => {
      toast.error(err?.message ?? "Failed to create motor tariff.");
    },
  });
}

// ── Update ────────────────────────────────────────────────────────────────────
export function useUpdateMotorTariff() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      tariffKey,
      dto,
    }: {
      tariffKey: number;
      dto: MotorTariffDTO;
    }) => updateMotorTariff(tariffKey, dto),
    onSuccess: (res, { tariffKey }) => {
      qc.invalidateQueries({ queryKey: motorTariffKeys.all() });
      qc.invalidateQueries({ queryKey: motorTariffKeys.detail(tariffKey) });
      toast.success(res?.message ?? "Motor tariff updated successfully.");
    },
    onError: (err: { message?: string }) => {
      toast.error(err?.message ?? "Failed to update motor tariff.");
    },
  });
}

// ── Delete ────────────────────────────────────────────────────────────────────
export function useDeleteMotorTariff() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (tariffKey: number) => deleteMotorTariff(tariffKey),
    onSuccess: (_res, tariffKey) => {
      qc.invalidateQueries({ queryKey: motorTariffKeys.all() });
      qc.removeQueries({ queryKey: motorTariffKeys.detail(tariffKey) });
      toast.success("Motor tariff deleted successfully.");
    },
    onError: (err: { message?: string }) => {
      toast.error(err?.message ?? "Failed to delete motor tariff.");
    },
  });
}

// ── Hierarchy (cascading dropdowns) ──────────────────────────────────────────
export function useMotorHierarchy(
  level: "tariffType" | "groupOfVehicle" | "typeOfVehicle" | "category",
  filters: {
    tariffType?: string;
    groupOfVehicle?: string;
    typeOfVehicle?: string;
  }
) {
  const params = useMemo(() => {
    const p: Record<string, string | undefined> = {};
    if (level !== "tariffType" && filters.tariffType)
      p.tariffType = filters.tariffType;
    if (
      (level === "typeOfVehicle" || level === "category") &&
      filters.groupOfVehicle
    )
      p.groupOfVehicle = filters.groupOfVehicle;
    if (level === "category" && filters.typeOfVehicle)
      p.typeOfVehicle = filters.typeOfVehicle;
    return p;
  }, [level, filters.tariffType, filters.groupOfVehicle, filters.typeOfVehicle]);

  const enabled = (() => {
    if (level === "tariffType") return true;
    if (level === "groupOfVehicle") return Boolean(params.tariffType);
    if (level === "typeOfVehicle")
      return Boolean(params.tariffType && params.groupOfVehicle);
    if (level === "category")
      return Boolean(
        params.tariffType && params.groupOfVehicle && params.typeOfVehicle
      );
    return false;
  })();

  const { data, isLoading } = useQuery({
    queryKey: motorTariffKeys.hierarchy(level, params),
    queryFn: async () => {
      const res = await getMotorHierarchy({
        level,
        tariffType: params.tariffType,
        groupOfVehicle: params.groupOfVehicle,
        typeOfVehicle: params.typeOfVehicle,
      });
      return res.data ?? [];
    },
    enabled,
    staleTime: 10 * 60 * 1000,
  });

  return { options: data ?? [], isLoading };
}