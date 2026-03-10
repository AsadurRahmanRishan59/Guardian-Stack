// lib/api.client.ts
import { ApiErrorResponse, ApiFetchOptions, ApiResponse, HttpMethod, ServerResponse } from "@/types/api.types";
import { createServerError, handleServerError } from "./api/error-handling";

export const getApiBaseUrl = (): string => {
    return process.env.NEXT_PUBLIC_API_BASE_URL || '/api';
};

export const getBackendUrl = (): string => {
    return process.env.SPRING_BOOT_API_URL || 'http://localhost:6060';
};

function getCookie(name: string): string | undefined {
    if (typeof document === 'undefined') return undefined;
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

// ─── Public routes that should never trigger a redirect on auth failure ───────
//
// These are routes where unauthenticated users are expected.
// A guest visiting the landing page has no session cookie — that is normal,
// not an error. We must not redirect them to /signin.

const PUBLIC_PATHS = ['/', '/signin', '/signup', '/verify-otp', '/forgot-password', '/reset-password', '/unauthorized'];

function isPublicPath(): boolean {
    if (typeof window === 'undefined') return false;
    const pathname = window.location.pathname;
    return PUBLIC_PATHS.some(p => pathname === p || pathname.startsWith(p + '?'));
}

// ─── Singleton refresh promise ────────────────────────────────────────────────
//
// Problem: when the JWT expires, every in-flight React Query gets a 401
// simultaneously. Without this guard, each one independently calls
// /api/auth/refresh → Spring Boot /api/auth/public/refresh → rate limited.
//
// Solution: module-level promise. The first 401 creates it; all subsequent
// 401s in that tick await the same promise. Once resolved, everyone retries
// with the new token. The promise is cleared in .finally() so future
// expirations work normally.

let refreshPromise: Promise<void> | null = null;

async function attemptRefresh(baseUrl: string): Promise<void> {
    if (refreshPromise) return refreshPromise;

    refreshPromise = fetch(`${baseUrl}/auth/refresh`, {
        method: 'POST',
        credentials: 'include',
    }).then(async (refreshResponse) => {
        if (!refreshResponse.ok) {
            // Declare errorType at block scope so the throw below can always use it
            let errorType = 'session_expired';

            if (!isPublicPath()) {
                // On a protected route — parse the reason and redirect to signin
                try {
                    const errorData = await refreshResponse.json();
                    if (errorData.message) {
                        errorType = errorData.message.toLowerCase();
                    }
                } catch {
                    // ignore parse failure — keep default 'session_expired'
                }
                console.warn(`❌ Refresh failed on protected route. Reason: ${errorType}`);
                if (typeof window !== 'undefined') {
                    window.location.href = `/signin?error=${errorType}`;
                }
            } else {
                // Guest on public page — 401 is expected, don't redirect
                console.log('ℹ️ No session on public page — skipping redirect.');
            }

            // Always throw so the caller knows refresh failed.
            // Using a structured object so isServerError() matches it and
            // handleServerError passes it through with the correct statusCode.
            throw {
                success: false,
                message: errorType,
                statusCode: refreshResponse.status,
                data: null,
                timestamp: new Date().toISOString(),
            };
        }
        console.log('✅ Refresh successful.');
    }).finally(() => {
        refreshPromise = null;
    });

    return refreshPromise;
}

// ─── Core fetch ───────────────────────────────────────────────────────────────

export async function apiFetch<T = unknown>(
    endpoint: string,
    method: HttpMethod,
    options: ApiFetchOptions = {}
): Promise<ApiResponse<T>> {
    const { body, params, headers = {}, ...fetchOptions } = options;
    const baseUrl = getApiBaseUrl();
    const url = buildUrl(`${baseUrl}${endpoint}`, params);

    const xsrfToken = getCookie('XSRF-TOKEN');
    const finalHeaders = new Headers(headers as Record<string, string>);
    finalHeaders.set('Content-Type', 'application/json');

    if (xsrfToken && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
        finalHeaders.set('X-XSRF-TOKEN', xsrfToken);
    }

    const isAuthEndpoint =
        endpoint.includes('/auth/public/refresh') ||
        endpoint.includes('/auth/public/signin') ||
        endpoint.includes('/auth/refresh');

    try {
        let response = await fetch(url, {
            ...fetchOptions,
            method,
            headers: finalHeaders,
            credentials: 'include',
            body: body ? JSON.stringify(body) : undefined,
        });

        // ── Handle 401: attempt singleton refresh then retry once ─────────
        if (response.status === 401 && !isAuthEndpoint) {
            console.log('🔄 JWT expired, queuing refresh…');

            // attemptRefresh throws a structured ApiErrorResponse on failure.
            // That throw propagates out of this try block directly to the catch,
            // so the retry fetch below NEVER runs if refresh failed.
            await attemptRefresh(baseUrl);

            // Only reached if refresh succeeded ↓
            const newXsrfToken = getCookie('XSRF-TOKEN');
            if (newXsrfToken && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
                finalHeaders.set('X-XSRF-TOKEN', newXsrfToken);
            }

            response = await fetch(url, {
                ...fetchOptions,
                method,
                headers: finalHeaders,
                credentials: 'include',
                body: body ? JSON.stringify(body) : undefined,
            });
        }

        return await parseResponse<T>(response);
    } catch (error) {
        // Log structured errors properly — plain objects log as {} with
        // console.error(obj), so JSON.stringify gives the real content.
        if (error instanceof Error) {
            console.error('Client fetch error:', error.message);
        } else {
            console.error('Client fetch error:', JSON.stringify(error));
        }
        throw handleServerError(error);
    }
}

// ─── Response parser ──────────────────────────────────────────────────────────

async function parseResponse<T>(response: Response): Promise<ApiResponse<T>> {
    if (response.status === 204) {
        return {
            success: true,
            message: 'Success',
            data: null,
            timestamp: new Date().toISOString(),
        };
    }

    const contentType = response.headers.get('content-type');

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

    if (!response.ok || !data.success) {
        const error = data as ApiErrorResponse<T>;
        if (!('statusCode' in error)) {
            (error as ApiErrorResponse<T>).statusCode = response.status;
        }
        throw error;
    }

    return data as ApiResponse<T>;
}

// ─── API surface ──────────────────────────────────────────────────────────────

export const api = {
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