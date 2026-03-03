// features/admin/user/user.types.ts
import { AppRole, Role } from "@/types/auth.types";

export enum SignUpMethod {
  ADMIN_CREATED = "ADMIN_CREATED",
  EMAIL = "EMAIL",
  MANUAL = "MANUAL",
}

// ─── List / Search View ───────────────────────────────────────────────────────

export interface MasterAdminUserView {
  userId: number;
  username: string;
  email: string;
  enabled: boolean;
  accountLocked: boolean;
  accountExpired: boolean;
  credentialExpired: boolean;
  signUpMethod: SignUpMethod;
  roles: AppRole[];
  createdAt: string;
  createdBy: string;
}

export interface MasterAdminUserViewSearchCriteria {
  username?: string;
  email?: string;
  enabled?: boolean;
  accountLocked?: boolean;
  accountExpired?: boolean;
  credentialExpired?: boolean;
  signUpMethod?: SignUpMethod;
  roleIds?: number[];
  page?: number;
  size?: number;
  sortBy?: MasterAdminUserViewSortOption;
  sortDirection?: "asc" | "desc";
}

export type MasterAdminUserViewSortOption =
  | "userId"
  | "username"
  | "createdAt"
  | "createdBy";

export interface MasterAdminUserViewFilterOptions {
  activeStatuses: boolean[];
  accountLockStatuses: boolean[];
  accountExpireStatuses: boolean[];
  credentialExpireStatuses: boolean[];
  signUpMethods: SignUpMethod[];
  roles: Role[];
  sortOptions?: MasterAdminUserViewSortOption[];
}

// ─── Detail DTO (GET /users/:id) ─────────────────────────────────────────────
// Mirrors what the backend actually returns for a single user.

export interface MasterAdminUserDTO {
  userId: number;
  username: string;
  email: string;
  enabled: boolean;
  roles: Role[];
  signUpMethod?: SignUpMethod | null;

  // Account lifecycle (driven by expiry dates on the backend)
  accountLocked: boolean;
  accountExpired: boolean;
  credentialsExpired: boolean;
  accountExpiryDate?: string | null;       // ISO datetime string
  credentialsExpiryDate?: string | null;   // ISO datetime string
  lockedUntil?: string | null;             // ISO datetime string

  // Password policy
  mustChangePassword?: boolean | null;
  passwordValidityDays?: number | null;
  lastPasswordChange?: string | null;

  // Login forensics
  failedLoginAttempts?: number | null;
  lastFailedLogin?: string | null;
  lastSuccessfulLogin?: string | null;

  // Audit
  createdAt: string;
  updatedAt: string;
  createdBy?: string | null;
  updatedBy?: string | null;
}

// ─── Request DTOs (must exactly match backend records) ───────────────────────

/**
 * Matches backend CreateUserRequestDTO:
 *   username, email, password, roleIds,
 *   accountExpiryDate, passwordValidityDays, enabled, mustChangePassword
 */
export interface AdminUserCreateRequestDTO {
  username: string;
  email: string;
  password: string;
  roleIds: number[];
  enabled: boolean;
  mustChangePassword: boolean;
  passwordValidityDays?: number | null;
  accountExpiryDate?: string | null; // ISO datetime or null
}

/**
 * Matches backend UpdateUserRequestDTO:
 *   username, email, password, roleIds,
 *   enabled, mustChangePassword, passwordValidityDays,
 *   lockedUntil, accountExpiryDate, credentialsExpiryDate
 */
export interface AdminUserUpdateRequestDTO {
  username?: string;
  email: string;
  password?: string | null;
  roleIds: number[];
  enabled: boolean;
  mustChangePassword: boolean;
  passwordValidityDays?: number | null;
  lockedUntil?: string | null;
  accountExpiryDate?: string | null;
  credentialsExpiryDate?: string | null;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

export const isFlagActive = (flag?: boolean | null): boolean => flag === true;
export const isAccountLocked = (locked?: boolean | null): boolean => locked === true;
export const isExpired = (expired?: boolean | null): boolean => expired === true;