//types/api.types.ts

export interface ApiResponse<T = unknown> {
    success: boolean;
    message: string;
    data: T | null;
    pagination?: Pagination;
    timestamp?: string;
}

export interface Pagination {
    currentPage: number;
    pageSize: number;
    totalElements: number;
    totalPages: number;
    hasNext: boolean;
    hasPrevious: boolean;
    sortBy: string;
    sortDirection: string;
}

export interface Pagination {
  currentPage: number;
  pageSize: number;
  totalElements: number;
  totalPages: number;
  hasNext: boolean;
  hasPrevious: boolean;
  sortBy: string;
  sortDirection: string;
}

export interface PaginatedResponse<T> {
  success: boolean;
  message: string;
  data: T[];
  pagination: Pagination;
  timestamp: string;
}

export interface ApiErrorResponse<T = unknown> {
    data: T | null;
    message: string | string[];
    success: false;
    statusCode: number;
    timestamp: string;
}

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
export type ServerResponse<T = unknown> = ApiResponse<T> | ApiErrorResponse<T>;

export interface ApiFetchOptions extends Omit<RequestInit, 'body' | 'method'> {
    body?: unknown;
    params?: Record<string, string | number | boolean | null | undefined>;
}
