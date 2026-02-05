// features/admin/user/user.types.ts
import { AppRole, Role } from "@/types/auth.types";

export enum SignUpMethod {
  ADMIN_CREATED = "ADMIN_CREATED",
  EMAIL = "EMAIL",
  MANUAL = "MANUAL"
}

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
  sortDirection?: 'asc' | 'desc';
}

export type MasterAdminUserViewSortOption = 'userId' | 'username' | 'createdAt' | 'createdBy';

export interface MasterAdminUserViewFilterOptions {
  activeStatuses: boolean[];
  accountLockStatuses: boolean[];
  accountExpireStatuses: boolean[];
  credentialExpireStatuses: boolean[];
  signUpMethods: SignUpMethod[]
  roles: Role[];
  sortOptions?: MasterAdminUserViewSortOption[];
}

// Admin User Response DTO interface
// Updated Admin User Response DTO interface with proper null handling
export interface MasterAdminUserDTO {
  userId: number;
  username: string;
  email: string;
  roles: Role[]; // nested Role objects
  signUpMethod?: SignUpMethod | null;

  // Spring Security flags - these can be null when not explicitly set
  enabled: boolean;
  accountLocked?: boolean | null;
  accountExpired?: boolean | null;
  credentialsExpired?: boolean | null;

  // --- SECURITY & LOGIN FORENSICS ---
  failedLoginAttempts?: number | null;
  lastFailedLogin?: string | null;
  lastSuccessfulLogin?: string | null;
  lockedUntil?: string | null;

  // --- COMPLIANCE & LIFECYCLE MANAGEMENT ---
  accountExpiryDate?: string | null;
  credentialsExpiryDate?: string | null;
  lastPasswordChange?: string | null;
  mustChangePassword?: boolean | null;

  // --- SYSTEM AUDIT TRAIL ---
  createdAt: string;
  updatedAt: string;
  createdBy?: string | null;
  updatedBy?: string | null;
}

// Helper function to safely check boolean flags
// Treats null/undefined as false (no issue)
export const isFlagActive = (flag?: boolean | null): boolean => {
  return flag === true;
};

// Helper function to check if account is locked
// Returns true only if explicitly locked (true), not when null/undefined
export const isAccountLocked = (locked?: boolean | null): boolean => {
  return locked === true;
};

// Helper function to check if something is expired
// Returns true only if explicitly expired (true), not when null/undefined
export const isExpired = (expired?: boolean | null): boolean => {
  return expired === true;
};

export interface AdminUserCreateRequestDTO {
  username: string;
  email: string;
  password: string;
  enabled: boolean;
  accountNonExpired: boolean;
  accountNonLocked: boolean;
  credentialsNonExpired: boolean;
  credentialsExpiryDate: string;
  accountExpiryDate: string;
  twoFactorSecret: string;
  isTwoFactorEnabled: boolean;
  signUpMethod: string;
  roleIds: number[];
}

export interface AdminUserUpdateRequestDTO {
  email: string;
  password: string;
  enabled: boolean;
  accountNonExpired: boolean;
  accountNonLocked: boolean;
  credentialsNonExpired: boolean;
  credentialsExpiryDate: string;
  accountExpiryDate: string;
  twoFactorSecret: string;
  isTwoFactorEnabled: boolean;
  signUpMethod: string;
  roleIds: number[];
}
