// lib/api/auth.service.ts
// Authentication service - calls Next.js API routes

import { LoginCredentials, LoginResponseDTO, UserResponse } from '@/types/auth.types';
import { apiClient, ApiResponse } from './api-client';


// interface RegisterData {
//   username: string;
//   email: string;
//   password: string;
//   confirmPassword: string;
// }

class AuthService {
  private static instance: AuthService;

  private constructor() {}

  static getInstance(): AuthService {
    if (!AuthService.instance) {
      AuthService.instance = new AuthService();
    }
    return AuthService.instance;
  }

  // Login - calls Next.js API route
  async login(credentials: LoginCredentials): Promise<ApiResponse<LoginResponseDTO>> {
    return apiClient.post<LoginResponseDTO>('/api/auth/login', credentials);
  }

  // Logout
  async logout(): Promise<void> {
    try {
      await apiClient.post('/api/auth/logout');
    } finally {
      if (typeof window !== 'undefined') {
        window.location.href = '/login';
      }
    }
  }

  // Register
  // async register(data: RegisterData): Promise<ApiResponse<any>> {
  //   return apiClient.post('/api/auth/register', data);
  // }

  // Get current user
  async getCurrentUser(): Promise<ApiResponse<UserResponse>> {
    return apiClient.get('/api/auth/me');
  }

  // Check authentication status
  async checkAuth(): Promise<boolean> {
    try {
      const response = await apiClient.get('/api/auth/check');
      return response.success;
    } catch {
      return false;
    }
  }
}

export const authService = AuthService.getInstance();
