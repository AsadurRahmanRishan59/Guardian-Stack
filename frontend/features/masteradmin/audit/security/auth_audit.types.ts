// features/masteradmin/audit/security/auth_audit.types.ts

// ─── Enums ────────────────────────────────────────────────────────────────────

/** Mirrors AuditEventType.AuditLevel on the backend. */
export type AuditLevel = "DEBUG" | "INFO" | "WARN" | "CRITICAL";

// ─── LEFT PANEL ───────────────────────────────────────────────────────────────

export interface AuthAuditTimelineItemDTO {
  id:               number;
  eventType:        string;
  eventDescription: string;
  level:            AuditLevel;
  userEmail:        string | null;
  userId:           number | null;
  ipAddress:        string | null;
  userAgent:        string | null;
  /**
   * Per-request correlation UUID (X-Request-ID / ELK trace.id).
   * Null for rows written before the request_id migration was applied.
   */
  requestId:        string | null;
  success:          boolean;
  failureReason:    string | null;
  additionalInfo:   string | null;
  timestamp:        string;
}

// ─── FILTER ───────────────────────────────────────────────────────────────────

export interface AuthAuditFilterRequest {
  eventType?:  string;
  userEmail?:  string;
  ipAddress?:  string;
  /**
   * Exact UUID match. Paste the X-Request-ID header value from browser
   * dev-tools or the trace.id from a Kibana document to surface the
   * corresponding DB row instantly.
   */
  requestId?:  string;
  success?:    boolean;
  from?:       string;   // ISO-8601
  to?:         string;   // ISO-8601
  page?:       number;
  size?:       number;
}