// features/masteradmin/tariff/motor/motor.tariff.service.ts
import { api } from "@/lib/api.client";
import type { ApiResponse } from "@/types/api.types";
import type {
  MotorTariffDTO,
  MotorTariffFullDTO,
  MotorTariffShortView,
  MotorTariffSearchCriteria,
  MotorHierarchyParams,
} from "./motor.tariff.types";

// ── Master Admin endpoints (/master-admin/tariff/motor) ───────────────────────

/**
 * GET /master-admin/tariff/motor
 * Paginated lightweight table view — MotorTariffShortView
 */
export function getMotorTariffs(
  criteria?: MotorTariffSearchCriteria
): Promise<ApiResponse<MotorTariffShortView[]>> {
  return api.client.get<MotorTariffShortView[]>(
    "/master-admin/tariffs/motor",
    criteria as Record<string, string | number | boolean | null | undefined>
  );
}

/**
 * GET /master-admin/tariff/motor/:tariffKey
 * Full detail view — MotorTariffFullDTO
 */
export function getMotorTariffById(
  tariffKey: number
): Promise<ApiResponse<MotorTariffFullDTO>> {
  return api.client.get<MotorTariffFullDTO>(
    `/master-admin/tariffs/motor/${tariffKey}`
  );
}

/**
 * POST /master-admin/tariff/motor
 * Create a new tariff entry
 */
export function createMotorTariff(
  dto: MotorTariffDTO
): Promise<ApiResponse<MotorTariffDTO>> {
  return api.client.post<MotorTariffDTO>("/master-admin/tariffs/motor", dto);
}

/**
 * PUT /master-admin/tariff/motor/:tariffKey
 * Full update
 */
export function updateMotorTariff(
  tariffKey: number,
  dto: MotorTariffDTO
): Promise<ApiResponse<MotorTariffDTO>> {
  return api.client.put<MotorTariffDTO>(
    `/master-admin/tariffs/motor/${tariffKey}`,
    dto
  );
}

/**
 * DELETE /master-admin/tariff/motor/:tariffKey
 */
export function deleteMotorTariff(
  tariffKey: number
): Promise<ApiResponse<void>> {
  return api.client.delete<void>(`/master-admin/tariffs/motor/${tariffKey}`);
}

// ── Public hierarchy endpoint (/tariff/motor/hierarchy) ───────────────────────

/**
 * GET /tariff/motor/hierarchy
 * Cascading dropdown data for tariff type → group → type → category
 */
export function getMotorHierarchy(
  params: MotorHierarchyParams
): Promise<ApiResponse<string[]>> {
  const queryParams: Record<string, string> = { level: params.level };
  if (params.tariffType) queryParams.tariffType = params.tariffType;
  if (params.groupOfVehicle) queryParams.groupOfVehicle = params.groupOfVehicle;
  if (params.typeOfVehicle) queryParams.typeOfVehicle = params.typeOfVehicle;

  return api.client.get<string[]>("/master-admin/tariffs/motor/hierarchy", queryParams);
}