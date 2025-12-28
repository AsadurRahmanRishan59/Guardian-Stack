// lib/api/api-client.ts
// Frontend API Client - calls Next.js API routes (not directly to Spring Boot)

import { ApiResponse } from "@/types/api.types";

interface RequestConfig extends RequestInit {
  params?: Record<string, any>;
}



class ApiClient {
  private static instance: ApiClient;

  private constructor() { }

  static getInstance(): ApiClient {
    if (!ApiClient.instance) {
      ApiClient.instance = new ApiClient();
    }
    return ApiClient.instance;
  }

  // Build URL with query parameters
  private buildUrl(endpoint: string, params?: Record<string, any>): string {
    if (!params) return endpoint;

    const queryParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        queryParams.append(key, String(value));
      }
    });

    const queryString = queryParams.toString();
    return queryString ? `${endpoint}?${queryString}` : endpoint;
  }

  // Main request method
  private async request<T = any>(
    endpoint: string,
    config: RequestConfig = {}
  ): Promise<ApiResponse<T>> {
    const { params, ...fetchConfig } = config;
    const url = this.buildUrl(endpoint, params);

    const requestConfig: RequestInit = {
      ...fetchConfig,
      credentials: 'include', // Important for cookies
      headers: {
        'Content-Type': 'application/json',
        ...fetchConfig.headers,
      },
    };

    try {
      const response = await fetch(url, requestConfig);

      // Handle non-JSON responses (like file downloads)
      const contentType = response.headers.get('content-type');
      if (contentType && !contentType.includes('application/json')) {
        if (response.ok) {
          return {
            success: true,
            message: 'Request successful',
            data: response as any,
            timestamp: new Date().toISOString(),
          };
        }
      }

      // Parse JSON response
      const data: ApiResponse<T> = await response.json();

      // Handle 401 Unauthorized - redirect to login
      if (response.status === 401) {
        if (typeof window !== 'undefined') {
          window.location.href = '/login';
        }
      }

      // Throw error if response is not ok
      if (!response.ok) {
        throw data;
      }

      return data;
    } catch (error: any) {
      if (error.statusCode) {
        throw error;
      }

      throw {
        success: false,
        message: error.message || 'Network error occurred',
        statusCode: 500,
        data: null,
        timestamp: new Date().toISOString(),
      };
    }
  }

  // GET request
  async get<T = any>(endpoint: string, params?: Record<string, any>): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, { method: 'GET', params });
  }

  // POST request
  async post<T = any>(endpoint: string, body?: any): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  // PUT request
  async put<T = any>(endpoint: string, body?: any): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      method: 'PUT',
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  // DELETE request
  async delete<T = any>(endpoint: string): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, { method: 'DELETE' });
  }

  // PATCH request
  async patch<T = any>(endpoint: string, body?: any): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      method: 'PATCH',
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  // Download file
  async downloadFile(endpoint: string, filename?: string): Promise<void> {
    const response = await fetch(endpoint, {
      method: 'GET',
      credentials: 'include',
    });

    if (!response.ok) {
      throw new Error('Download failed');
    }

    const blob = await response.blob();

    const contentDisposition = response.headers.get('Content-Disposition');
    const filenameMatch = contentDisposition?.match(/filename="?(.+)"?/);
    const finalFilename = filename || filenameMatch?.[1] || 'download.pdf';

    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = finalFilename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(downloadUrl);
  }
}

export const apiClient = ApiClient.getInstance();
export type { ApiResponse, RequestConfig };