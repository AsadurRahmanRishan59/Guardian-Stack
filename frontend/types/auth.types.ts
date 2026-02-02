// types/auth.types.ts

export enum AppRole {
  MASTER_ADMIN = "ROLE_MASTER_ADMIN",
  ADMIN = "ROLE_ADMIN",
  EMPLOYEE = "ROLE_EMPLOYEE",
  USER = "ROLE_USER"
}

export interface Role {
  roleId: number;
  roleName: AppRole;
  description?: string | null;
}

export interface UserResponse {
  userId: number;
  username: string;
  email: string;
  roles: AppRole[];
  enabled: boolean;
}

export interface LoginResponseDTO {
  jwtToken: string;
  refreshToken: string;
  userResponse: UserResponse;
}

export interface SignupRequest {
  username: string;
  email: string;
  password: string;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface VerifyOTPData {
  email: string;
  otp: string;
}

export interface PasswordResetRequest {
  email: string;
  otp: string;
  newPassword: string;
}

export interface AuthState {
  user: UserResponse | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}