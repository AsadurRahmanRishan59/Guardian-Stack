// features/admin/user/user.types.ts

import { AppRole, Role } from "@/types/auth.types";

export enum SignUpMethod {
  ADMIN_CREATED = "ADMIN_CREATED",
  Email = "Email"
}
export interface AdminUserView {
  userId: number;
  username: string;
  email: string;
  signUpMethod: string;
  isTwoFactorEnabled: boolean;
  roles: AppRole[];
  enabled: boolean;
  createdDate: string;
}

export interface AdminUserViewSearchCriteria {
  username?: string;
  enabled?: boolean;
  isTwoFactorEnabled?: boolean;
  signUpMethod?: SignUpMethod;
  roleId?: number;
  page?: number;
  size?: number;
  sortBy?: string;
  sortDirection?: 'asc' | 'desc';
}
export type SortOption = 'userId' | 'username' | 'createdDate';

export interface AdminUserViewFilterOptions {
  activeStatuses: boolean[];
  twoFactorStatuses: boolean[];
  signUpMethods: SignUpMethod[]
  roles: Role[];
  sortOptions?: SortOption[];
}

// Admin User Response DTO interface
export interface AdminUserResponseDTO {
  userId: number;
  username: string;
  email: string;

  // Spring Security flags
  enabled: boolean;
  accountNonExpired: boolean;
  accountNonLocked: boolean;
  credentialsNonExpired: boolean;

  credentialsExpiryDate: string; // ISO date string
  accountExpiryDate: string; // ISO date string

  twoFactorSecret?: string | null;
  isTwoFactorEnabled: boolean;
  signUpMethod?: SignUpMethod | null;

  roles: Role[]; // nested Role objects

  createdDate: string; // ISO datetime string
  updatedDate: string; // ISO datetime string
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
