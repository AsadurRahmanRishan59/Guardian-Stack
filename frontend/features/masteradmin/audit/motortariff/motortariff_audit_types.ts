// features/masteradmin/audit/motortariff/motortariff.types.ts

// ─── Enums ─────────────────────────────────────────────────────────────────

export type RevisionType = 'CREATED' | 'MODIFIED' | 'DELETED';
export type FieldType    = 'BOOLEAN' | 'STRING'   | 'DECIMAL' | 'PERCENT';

// ─── LEFT PANEL ────────────────────────────────────────────────────────────
// Slim DTO — one per timeline node

export interface MotorTariffAuditTimelineItemDTO {
  revisionNumber: number;
  revisionType:   RevisionType;
  timestamp:      string;       // ISO-8601 LocalDateTime
  changedBy:      string;
  ipAddress:      string;

  tariffKey:      number;
  tariffType:     string;
  groupOfVehicle: string;
  typeOfVehicle:  string;
  category:       string;

  isActive:       boolean;
  statusChanged:  boolean;      // pre-computed: isActive flipped vs predecessor
}

// ─── RIGHT PANEL ───────────────────────────────────────────────────────────
// Full DTO — loaded on click

export interface MotorTariffAuditDTO {
  revisionNumber:  number;
  revisionType:    RevisionType;
  timestamp:       string;
  changedBy:       string;
  ipAddress:       string;

  tariffKey:       number;
  tariffType:      string;
  groupOfVehicle:  string;
  typeOfVehicle:   string;
  category:        string;

  ownDpBasic:      string;
  fullInsValue:    string;
  actLiability:    string;
  fire:            string;
  theft:           string;
  cyclone:         string;
  earthquake:      string;

  isActive:        boolean;
  diff:            MotorTariffAuditDiffDTO | null;
}

// ─── DIFF ──────────────────────────────────────────────────────────────────

export interface MotorTariffAuditDiffDTO {
  previousRevisionNumber: number | null;
  previousChangedBy:      string | null;
  changedFields:          DiffField[];
  unchangedFields:        DiffField[];
  criticalChange:         boolean;
}

export interface DiffField {
  fieldName:     string;
  fieldLabel:    string;
  fieldType:     FieldType;
  previousValue: string;
  currentValue:  string;
  critical:      boolean;
}

// ─── FILTER ────────────────────────────────────────────────────────────────

export interface MotorTariffAuditFilterRequest {
  tariffKey?:      number;
  tariffType?:     string;
  changedBy?:      string;
  ipAddress?:      string;
  revisionTypes?:  string;     // comma-separated: "CREATED,MODIFIED"
  from?:           string;     // ISO-8601
  to?:             string;     // ISO-8601
  page?:           number;
  size?:           number;
}