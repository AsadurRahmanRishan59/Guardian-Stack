// features/masteradmin/audit/user/user.types.ts

// ─── Enums ─────────────────────────────────────────────────────────────────

export type RevisionType = 'CREATED' | 'MODIFIED' | 'DELETED';
export type FieldType    = 'BOOLEAN'  | 'STRING'   | 'ROLES'   | 'DATETIME';

// ─── LEFT PANEL ────────────────────────────────────────────────────────────
// Slim DTO — one per timeline node

export interface AuditTimelineItemDTO {
  revisionNumber:        number;
  revisionType:          RevisionType;
  timestamp:             string;        // ISO-8601 LocalDateTime
  changedBy:             string;
  ipAddress:             string;
  userId:                number;
  email:                 string;
  accountLocked:         boolean;
  enabled:               boolean;
  hasAdminRoleEscalation: boolean;      // pre-computed by backend
}

// ─── RIGHT PANEL ───────────────────────────────────────────────────────────
// Full DTO — loaded on click, includes diff

export interface MasterAdminUserAuditDTO {
  revisionNumber:        number;
  revisionType:          RevisionType;
  timestamp:             string;
  changedBy:             string;
  ipAddress:             string;
  userId:                number;
  username:              string;
  email:                 string;
  signUpMethod:          string;
  roles:                 string[];
  enabled:               boolean;
  accountLocked:         boolean;
  accountExpiryDate:     string | null;
  credentialsExpiryDate: string | null;
  lastPasswordChange:    string | null;
  diff:                  AuditDiffDTO | null;   // null only for first-ever revision
}

// ─── DIFF ──────────────────────────────────────────────────────────────────

export interface AuditDiffDTO {
  previousRevisionNumber: number | null;
  previousChangedBy:      string | null;
  changedFields:          DiffField[];
  unchangedFields:        DiffField[];
  addedRoles:             string[];
  removedRoles:           string[];
  criticalChange:         boolean;
  adminEscalation:        boolean;
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

export interface AuditFilterRequest {
  userId?:        number;
  email?:         string;
  changedBy?:     string;
  ipAddress?:     string;
  revisionTypes?: string;     // comma-separated: "CREATED,MODIFIED"
  from?:          string;     // ISO-8601
  to?:            string;     // ISO-8601
  page?:           number;
  size?:           number;
}