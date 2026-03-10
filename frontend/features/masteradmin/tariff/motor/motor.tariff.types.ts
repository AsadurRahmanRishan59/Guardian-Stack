import { MotorTariffRequestFormValues } from "./motor.tariff.schema";

type MotorTariffType =
  "Private Vehicle"
  | "Motor Cycle"
  | "Commercial Vehicle";

type MotorTariffGroupOfVehicle =
  "Passenger Vehicle/Goods Carrying"
  | "Trailer"
  | "Class A Goods Carrying Vehicles"
  | "Class B(1,0) Goods Carrying Vehicles"
  | "Class B(1,0) Passenger Carrying Vehicles"
  | "Class B(2,0) Passenger Carrying Vehicles"
  | "Class C Passenger Carrying Vehicles"
  | "Class D Miscellaneous & Special Types of Vehicles"
  | "Auto Cycles or Mechanically Assisted Pedal Cycles"
  | "MotorCycle/Scooter";


// import { AgentRequestFormValues } from "./agent.schema";

export interface MotorTariff {
  tariffKey: number,
  tariffType: MotorTariffType,
  groupOfVehicle: MotorTariffGroupOfVehicle,
  typeOfVehicle: string,
  category: string,
  ownDpBasic: number,
  fullInsValue: number,
  actLiability: number,
  fire: number,
  theft: number,
  cyclone: number,
  earthquake: number,
  others: number,
  isActive: boolean;
  createdAt: string;
  lastUpdatedAt: string;
}

export interface MotorTariffRequest {
  tariffType: MotorTariffType,
  groupOfVehicle: MotorTariffGroupOfVehicle,
  typeOfVehicle: string,
  category: string,
  ownDpBasic: number,
  fullInsValue: number,
  actLiability: number,
  fire: number,
  theft: number,
  cyclone: number,
  earthquake: number,
  others: number,
  isActive: boolean;
}

export interface MotorTariffAdminView {
  tariffKey: number,
  tariffType: MotorTariffType,
  groupOfVehicle: MotorTariffGroupOfVehicle,
  typeOfVehicle: string,
  category: string,
  ownDpBasic: number,
  fullInsValue: number,
  actLiability: number,
  isActive: boolean;
}

type SortOption = "tariffKey" | "tariffType" | "groupOfVehicle" | "typeOfVehicle" | "category"


// export interface MotorTariffSearchCriteria {
//   // Search
//   tariffKey?: number,

//   // Filters
//   tariffType?: MotorTariffType,
//   groupOfVehicle?: MotorTariffGroupOfVehicle,
//   typeOfVehicle?: string,
//   category?: string,
//   isActive?: boolean;

//   // Pagination
//   page?: number,
//   size?: number,

//   // Sorting
//   sortBy?: SortOption,
//   sortDirection?: 'asc' | 'desc';
// }


export interface MotorTariffSearchCriteria {
  // Search
  tariffKey?: number,

  // Filters
  tariffType?: string,
  groupOfVehicle?: string,
  typeOfVehicle?: string,
  category?: string,
  isActive?: boolean;

  // Pagination
  page?: number,
  size?: number,

  // Sorting
  sortBy?: SortOption,
  sortDirection?: 'asc' | 'desc';
}

export interface MotorHierarchy{
level?:string,
tariffType?:string,
groupOfVehicle?:string,
typeOfVehicle?:string,
}

export interface MotorTariffFormProps {
  onSubmit: (data: MotorTariffRequestFormValues) => void;
  isLoading?: boolean;
  initialData?: MotorTariff | null;
  mode?: "create" | "edit";
  serverErrors?: Record<string, string> | string[]; // Support both formats
}