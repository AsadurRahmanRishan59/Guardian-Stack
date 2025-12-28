// types/auth.types.ts
// Define user roles and types

// export enum UserRole {
//     ADMIN = 'ROLE_ADMIN',
//     ACCOUNT_MANAGER = 'ROLE_ACCOUNT_MANAGER',
//     ACCOUNT_USER = 'ROLE_ACCOUNT_USER',
// }

export enum AppRole {
  MASTER_ADMIN = "ROLE_MASTER_ADMIN,",
  ADMIN = "ROLE_ADMIN",
  EMPLOYEE = "ROLE_EMPLOYEE",
  USER = "ROLE_USER"
}

// Role interface (maps Role entity)
export interface Role {
  roleId: number;
  roleName: AppRole;
  description?: string | null;
}


export interface LoginCredentials {
  email: string;
  password: string;
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
  xsrfToken: string;
  xsrfHeaderName: string;
  userResponse: UserResponse;
}


export interface AuthState {
  user: UserResponse | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}


