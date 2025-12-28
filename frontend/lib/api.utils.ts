// lib/utils/api.utils.ts
// Generic API utility with JWT and XSRF token handling

// import { cookies } from 'next/headers';
import { createServerError, handleServerError } from './api/error-handling';
import { ApiErrorResponse, ApiResponse } from '@/types/api.types';

// ============================================================================
// Type Definitions
// ============================================================================


// Union type for all server responses
export type ServerResponse<T = unknown> = ApiResponse<T> | ApiErrorResponse<T>;

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

// ============================================================================
// Environment Configuration
// ============================================================================


export const getBackendUrl = (): string => {
    return process.env.SPRING_BOOT_API_URL || 'http://localhost:6080';
};

// ============================================================================
// Server-Side Auth Helpers
// ============================================================================

/**
 * Get authentication headers for server-side requests
 * Includes JWT Bearer token and XSRF token (XSRF only for non-GET methods)
 */
// export async function getAuthHeaders(method: HttpMethod = 'GET'): Promise<HeadersInit> {
//     const cookieStore = await cookies();
//     const jwtToken = cookieStore.get('jwt_token')?.value;
//     const xsrfToken = cookieStore.get('XSRF-TOKEN')?.value;

//     const headers: HeadersInit = {
//         'Content-Type': 'application/json',
//     };

//     // Always include JWT token for authenticated requests
//     if (jwtToken) {
//         headers['Authorization'] = `Bearer ${jwtToken}`;
//     }

//     // Include XSRF token only for non-GET methods (POST, PUT, PATCH, DELETE)
//     if (xsrfToken && method !== 'GET') {
//         headers['X-XSRF-TOKEN'] = xsrfToken;
//     }

//     return headers;
// }

/**
 * Check if user is authenticated (server-side)
 */
// export async function checkAuth(): Promise<boolean> {
//     const cookieStore = await cookies();
//     const jwtToken = cookieStore.get('jwt_token')?.value;
//     return !!jwtToken;
// }

/**
 * Get both JWT and XSRF tokens (server-side)
 */
// export async function getAuthTokens(): Promise<{
//     jwtToken: string | undefined;
//     xsrfToken: string | undefined;
// }> {
//     const cookieStore = await cookies();
//     return {
//         jwtToken: cookieStore.get('jwt_token')?.value,
//         xsrfToken: cookieStore.get('XSRF-TOKEN')?.value,
//     };
// }

/**
 * Clear authentication cookies (server-side)
 */
// export async function clearAuthCookies(): Promise<void> {
//     const cookieStore = await cookies();
//     cookieStore.delete('jwt_token');
//     cookieStore.delete('XSRF-TOKEN');
// }

// ============================================================================
// Error Handling
// ============================================================================



// ============================================================================
// Server-Side API Fetch (for Next.js API routes)
// ============================================================================

interface BackendFetchOptions extends Omit<RequestInit, 'body' | 'method'> {
    body?: unknown;
    includeAuth?: boolean;
}

/**
 * Fetch from Spring Boot backend (server-side only)
 * Automatically includes JWT and XSRF tokens if includeAuth is true
 * XSRF token is only included for non-GET methods
 */
// export async function backendFetch<T = unknown>(
//     endpoint: string,
//     method: HttpMethod,
//     options: BackendFetchOptions = {}
// ): Promise<ApiResponse<T>> {
//     const { body, includeAuth = true, headers = {}, ...fetchOptions } = options;
//     const baseUrl = getBackendUrl();
//     const url = endpoint.startsWith('http') ? endpoint : `${baseUrl}${endpoint}`;

//     try {
//         let requestHeaders: HeadersInit = {
//             'Content-Type': 'application/json',
//             ...headers,
//         };

//         // Add auth headers if requested (XSRF only for non-GET methods)
//         if (includeAuth) {
//             const authHeaders = await getAuthHeaders(method);
//             requestHeaders = { ...requestHeaders, ...authHeaders };
//         }

//         const response = await fetch(url, {
//             ...fetchOptions,
//             method,
//             headers: requestHeaders,
//             credentials: 'include',
//             body: body ? JSON.stringify(body) : undefined,
//         });

//         return await parseResponse<T>(response);
//     } catch (error) {
//         console.error('Backend fetch error:', error);
//         throw handleServerError(error);
//     }
// }

// ============================================================================
// Client-Side API Fetch (calls Next.js API routes)
// ============================================================================

interface ApiFetchOptions extends Omit<RequestInit, 'body' | 'method'> {
    body?: unknown;
    params?: Record<string, string | number | boolean | null | undefined>;
}

/**
 * Fetch from Next.js API routes (client-side)
 * API routes will handle auth automatically via cookies
 */
export async function apiFetch<T = unknown>(
    endpoint: string,
    method: HttpMethod,
    options: ApiFetchOptions = {}
): Promise<ApiResponse<T>> {
    const { body, params, headers = {}, ...fetchOptions } = options;
    const baseUrl = getApiBaseUrl();
    const url = buildUrl(`${baseUrl}${endpoint}`, params);

    try {
        const response = await fetch(url, {
            ...fetchOptions,
            method,
            headers: {
                'Content-Type': 'application/json',
                ...headers,
            },
            credentials: 'include',
            body: body ? JSON.stringify(body) : undefined,
        });

        return await parseResponse<T>(response);
    } catch (error) {
        console.error('Client fetch error:', error);
        throw handleServerError(error);
    }
}

// ============================================================================
// Response Parsing
// ============================================================================

async function parseResponse<T>(response: Response): Promise<ApiResponse<T>> {
    // Handle 204 No Content
    if (response.status === 204) {
        return {
            success: true,
            message: 'Success',
            data: null,
            timestamp: new Date().toISOString(),
        };
    }

    const contentType = response.headers.get('content-type');

    // Handle non-JSON responses (like file downloads)
    if (contentType && !contentType.includes('application/json')) {
        if (response.ok) {
            return {
                success: true,
                message: 'Success',
                data: response as unknown as T,
                timestamp: new Date().toISOString(),
            };
        }
    }

    // Parse JSON response
    let data: ServerResponse<T>;
    try {
        data = await response.json();
    } catch (parseError) {
        throw createServerError(
            `Failed to parse response: ${response.statusText}` || parseError as string,
            response.status,
            null
        );
    }

    // Throw error if response is not ok
    if (!response.ok || !data.success) {
        // Add statusCode to error if not present
        const error = data as ApiErrorResponse<T>;
        if (!('statusCode' in error)) {
            (error as ApiErrorResponse<T>).statusCode = response.status;
        }
        throw error;
    }

    return data as ApiResponse<T>;
}

// ============================================================================
// URL Building
// ============================================================================

function buildUrl(
    endpoint: string,
    params?: Record<string, string | number | boolean | null | undefined>
): string {
    if (!params) return endpoint;

    const queryParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
            if (Array.isArray(value)) {
                value.forEach((v) => queryParams.append(key, String(v)));
            } else {
                queryParams.append(key, String(value));
            }
        }
    });

    const queryString = queryParams.toString();
    return queryString ? `${endpoint}?${queryString}` : endpoint;
}

// ============================================================================
// Convenience Methods
// ============================================================================

export const api = {
    // Client-side methods (call Next.js API routes)
    client: {
        get: <T = unknown>(
            endpoint: string,
            params?: Record<string, string | number | boolean | null | undefined>
        ): Promise<ApiResponse<T>> =>
            apiFetch<T>(endpoint, 'GET', { params }),

        post: <T = unknown>(endpoint: string, body?: unknown): Promise<ApiResponse<T>> =>
            apiFetch<T>(endpoint, 'POST', { body }),

        put: <T = unknown>(endpoint: string, body?: unknown): Promise<ApiResponse<T>> =>
            apiFetch<T>(endpoint, 'PUT', { body }),

        patch: <T = unknown>(endpoint: string, body?: unknown): Promise<ApiResponse<T>> =>
            apiFetch<T>(endpoint, 'PATCH', { body }),

        delete: <T = unknown>(endpoint: string): Promise<ApiResponse<T>> =>
            apiFetch<T>(endpoint, 'DELETE'),
    },

    // Server-side methods (call Spring Boot directly)
    // server: {
    //     get: <T = unknown>(
    //         endpoint: string,
    //         includeAuth = true
    //     ): Promise<ApiResponse<T>> =>
    //         backendFetch<T>(endpoint, 'GET', { includeAuth }),

    //     post: <T = unknown>(
    //         endpoint: string,
    //         body?: unknown,
    //         includeAuth = true
    //     ): Promise<ApiResponse<T>> =>
    //         backendFetch<T>(endpoint, 'POST', { body, includeAuth }),

    //     put: <T = unknown>(
    //         endpoint: string,
    //         body?: unknown,
    //         includeAuth = true
    //     ): Promise<ApiResponse<T>> =>
    //         backendFetch<T>(endpoint, 'PUT', { body, includeAuth }),

    //     patch: <T = unknown>(
    //         endpoint: string,
    //         body?: unknown,
    //         includeAuth = true
    //     ): Promise<ApiResponse<T>> =>
    //         backendFetch<T>(endpoint, 'PATCH', { body, includeAuth }),

    //     delete: <T = unknown>(
    //         endpoint: string,
    //         includeAuth = true
    //     ): Promise<ApiResponse<T>> =>
    //         backendFetch<T>(endpoint, 'DELETE', { includeAuth }),
    // },
};

// ============================================================================
// File Download Utility (Client-side)
// ============================================================================

export async function downloadFile(
    endpoint: string,
    filename?: string
): Promise<void> {
    const baseUrl = getApiBaseUrl();
    const url = `${baseUrl}${endpoint}`;

    const response = await fetch(url, {
        method: 'GET',
        credentials: 'include',
    });

    if (!response.ok) {
        const error = await response.json().catch(() =>
            createServerError(
                'Download failed',
                response.status,
                null
            )
        );
        throw error;
    }

    const blob = await response.blob();

    // Extract filename from Content-Disposition header
    const contentDisposition = response.headers.get('Content-Disposition');
    const filenameMatch = contentDisposition?.match(
        /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/
    );
    const finalFilename =
        filename ||
        filenameMatch?.[1]?.replace(/['"]/g, '') ||
        'download';

    // Create download link
    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = finalFilename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(downloadUrl);
}