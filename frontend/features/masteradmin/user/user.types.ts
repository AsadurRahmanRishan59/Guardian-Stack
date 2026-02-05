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
export interface MasterAdminUserDTO {
  userId: number;
  username: string;
  email: string;
  roles: Role[]; // nested Role objects
  signUpMethod?: SignUpMethod | null;

  // Spring Security flags
  enabled: boolean;
  accountLocked: boolean;
  accountExpired: boolean;
  credentialsExpired: boolean;

  // --- SECURITY & LOGIN FORENSICS ---
  failedLoginAttempts: number;
  lastFailedLogin: string;
  lastSuccessfulLogin: string;
  lockedUntil: string;

  // --- COMPLIANCE & LIFECYCLE MANAGEMENT ---
  accountExpiryDate: string;
  credentialsExpiryDate: string;
  lastPasswordChange: string;
  mustChangePassword: boolean;

  // --- SYSTEM AUDIT TRAIL ---
  createdAt: string;
  updatedAt: string;
  createdBy: string;
  updatedBy: string;
}

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
