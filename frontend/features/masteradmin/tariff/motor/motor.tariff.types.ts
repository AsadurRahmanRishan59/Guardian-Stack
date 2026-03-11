// features/masteradmin/tariff/motor/motor_tariff_types.ts

export enum TariffType {
  PRIVATE_VEHICLE = "Private Vehicle",
  MOTOR_CYCLE = "Motor Cycle",
  COMMERCIAL_VEHICLE = "Commercial Vehicle",
}

export type SortOption =
  | "tariffKey"
  | "tariffType"
  | "groupOfVehicle"
  | "typeOfVehicle"
  | "category";

// ── Matches backend: MotorTariffShortView (table row) ─────────────────────────
export interface MotorTariffShortView {
  tariffKey: number;
  tariffType: TariffType;
  groupOfVehicle: string;
  typeOfVehicle: string;
  category: string;
  ownDpBasic: number;
  fullInsValue: number;
  actLiability: number;
  isActive: boolean;
}

// ── Matches backend: MotorTariffFullDTO (view modal) ──────────────────────────
export interface MotorTariffFullDTO {
  tariffKey: number;
  tariffType: TariffType;
  groupOfVehicle: string;
  typeOfVehicle: string;
  category: string;
  ownDpBasic: number;
  fullInsValue: number;
  actLiability: number;
  fire: number;
  theft: number;
  cyclone: number;
  earthquake: number;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
  createdBy: string | null;
  updatedBy: string | null;
}

// ── Matches backend: MotorTariffDTO (create / update body) ────────────────────
export interface MotorTariffDTO {
  tariffKey?: number | null;
  tariffType: TariffType;
  groupOfVehicle: string;
  typeOfVehicle: string;
  category: string;
  ownDpBasic: number;
  fullInsValue: number;
  actLiability: number;
  fire: number;
  theft: number;
  cyclone: number;
  earthquake: number;
  isActive: boolean;
}

// ── Matches backend: MotorTariffMasterAdminViewSearchCriteria ─────────────────
export interface MotorTariffSearchCriteria {
  tariffKey?: number;
  tariffType?: TariffType;
  groupOfVehicle?: string;
  typeOfVehicle?: string;
  category?: string;
  isActive?: boolean;
  page?: number;
  size?: number;
  sortBy?: SortOption;
  sortDirection?: "asc" | "desc";
}

// ── Hierarchy query params ─────────────────────────────────────────────────────
export interface MotorHierarchyParams {
  level: "tariffType" | "groupOfVehicle" | "typeOfVehicle" | "category";
  tariffType?: string;
  groupOfVehicle?: string;
  typeOfVehicle?: string;
}