//lib/api.client.ts
import { ApiErrorResponse, ApiFetchOptions, ApiResponse, HttpMethod, ServerResponse } from "@/types/api.types";
import { createServerError, handleServerError } from "./api/error-handling";

export const getApiBaseUrl = (): string => {
    return process.env.NEXT_PUBLIC_API_BASE_URL || '/api';
};

export const getBackendUrl = (): string => {
    return process.env.SPRING_BOOT_API_URL || 'http://localhost:6060';
};


// Add this helper to your api client file
function getCookie(name: string): string | undefined {
    if (typeof document === 'undefined') return undefined; // Check if on server
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop()?.split(';').shift();
}


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


export async function apiFetch<T = unknown>(
    endpoint: string,
    method: HttpMethod,
    options: ApiFetchOptions = {}
): Promise<ApiResponse<T>> {
    const { body, params, headers = {}, ...fetchOptions } = options;
    const baseUrl = getApiBaseUrl();
    const url = buildUrl(`${baseUrl}${endpoint}`, params);

    // 1. Prepare Request
    const xsrfToken = getCookie('XSRF-TOKEN');
    const finalHeaders = new Headers(headers as Record<string, string>);
    finalHeaders.set('Content-Type', 'application/json');

    if (xsrfToken && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
        finalHeaders.set('X-XSRF-TOKEN', xsrfToken);
    }

    try {
        let response = await fetch(url, {
            ...fetchOptions,
            method,
            headers: finalHeaders,
            credentials: 'include',
            body: body ? JSON.stringify(body) : undefined,
        });

        // 2. INTERCEPT 401: Handle JWT Expiration
        // Don't retry if we are already trying to refresh or sign in
        const isAuthRequest = endpoint.includes('/auth/public/refresh') || endpoint.includes('/auth/public/signin');

        if (response.status === 401 && !isAuthRequest) {
            console.log('🔄 JWT Expired, attempting automatic refresh...');

            // Call your Next.js BFF refresh route
            const refreshResponse = await fetch(`${baseUrl}/auth/refresh`, {
                method: 'POST',
                credentials: 'include',
            });

            if (refreshResponse.ok) {
                console.log('✅ Refresh successful, retrying original request.');

                // Re-read the NEW XSRF token issued during refresh
                const newXsrfToken = getCookie('XSRF-TOKEN');
                if (newXsrfToken) {
                    finalHeaders.set('X-XSRF-TOKEN', newXsrfToken);
                }

                // Retry the original fetch
                response = await fetch(url, {
                    ...fetchOptions,
                    method,
                    headers: finalHeaders,
                    credentials: 'include',
                    body: body ? JSON.stringify(body) : undefined,
                });
            } else {
                // 1. Try to parse the error body to see WHY it failed
                let errorType = 'session_expired'; // Default fallback

                try {
                    const errorData = await refreshResponse.json();
                    // If your Spring Boot GlobalExceptionHandler sends the message, use it
                    if (errorData.message) {
                        errorType = errorData.message.toLowerCase();
                        // This will be 'session_displaced', 'session_reused', etc.
                    }
                } catch (_) { // Changed 'e' to '_'
                    console.warn('Could not parse refresh error body, using default.');
                }
                console.warn(`❌ Refresh failed. Reason: ${errorType}`);

                if (typeof window !== 'undefined') {
                    // 2. Pass the specific enum-like string to the URL
                    window.location.href = `/signin?error=${errorType}`;
                }

                throw new Error('Unauthorized');
            }
        }

        return await parseResponse<T>(response);
    } catch (error) {
        console.error('Client fetch error:', error);
        throw handleServerError(error);
    }
}


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


};
