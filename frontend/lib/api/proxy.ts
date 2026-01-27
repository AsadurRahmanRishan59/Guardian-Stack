// lib/api/proxy.ts
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { getBackendUrl } from '@/lib/api.client';
import { decryptToken, encryptToken } from '@/lib/api/crypto';
import { handleServerError } from '@/lib/api/error-handling';

interface ProxyOptions {
    requireAuth?: boolean;
    storeJwt?: boolean;
}

function buildBackendUrl(backendPath: string, request: NextRequest): string {
    const url = new URL(backendPath, getBackendUrl());

    // Copy query parameters from Next.js request to Spring Boot request
    request.nextUrl.searchParams.forEach((value, key) => {
        url.searchParams.append(key, value);
    });

    return url.toString();
}

export async function proxyToBackend(
    request: NextRequest,
    backendPath: string,
    options: ProxyOptions = {}
) {
    try {
        const { requireAuth = false, storeJwt = false } = options;

        const backendUrl = buildBackendUrl(backendPath, request);

        const headers: HeadersInit = {
            'Content-Type': 'application/json',
        };

        // CRITICAL: Forward browser headers to Spring Boot for device fingerprinting

        // 1. Client IP - Extract from Next.js request
        const clientIp = getClientIp(request);
        if (clientIp && clientIp !== 'unknown') {
            headers['X-Forwarded-For'] = clientIp;
            headers['X-Real-IP'] = clientIp;
        }

        // 2. User-Agent - MUST be forwarded from browser to Spring Boot
        const userAgent = request.headers.get('user-agent');
        if (userAgent) {
            headers['User-Agent'] = userAgent;
        } else {
            // Fallback for cases where User-Agent is missing
            headers['User-Agent'] = 'Unknown-Client';
        }

        // 3. Device ID - Custom header from client
        const deviceId = request.headers.get('x-device-id');
        if (deviceId) {
            headers['X-Device-ID'] = deviceId;
        } else {
            // This shouldn't happen, but provide fallback
            headers['X-Device-ID'] = 'no-device-id';
        }

        // 4. Add JWT if authentication required
        if (requireAuth) {
            const cookieStore = await cookies();
            const encryptedJwt = cookieStore.get('jwt_token')?.value;

            if (!encryptedJwt) {
                return NextResponse.json(
                    { success: false, message: 'Unauthorized' },
                    { status: 401 }
                );
            }

            const jwtToken = decryptToken(encryptedJwt);
            headers['Authorization'] = `Bearer ${jwtToken}`;
        }

        // Get request body for POST/PUT/PATCH
        let body: string | undefined;
        if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
            const jsonBody = await request.json();
            body = JSON.stringify(jsonBody);
        }

        // Forward to Spring Boot with all necessary headers
        const response = await fetch(backendUrl, { // Use backendUrl instead of SPRING_BOOT_URL + backendPath
            method: request.method,
            headers,
            body,
        });

        const data = await response.json();

        // Store JWT if this is a login/signup/refresh/verify-otp
        if (storeJwt && response.ok && data.success && data.data?.jwtToken) {
            const cookieStore = await cookies();
            const encryptedJwt = encryptToken(data.data.jwtToken);

            cookieStore.set('jwt_token', encryptedJwt, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax',
                path: '/',
                maxAge: 60 * 60 * 24 * 7, // 7 days
            });

            // Generate CSRF token on first authentication
            const csrfToken = crypto.randomUUID();
            cookieStore.set('XSRF-TOKEN', csrfToken, {
                httpOnly: false, // Must be readable by browser JS
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax',
                path: '/',
            });
        }

        // Forward important response headers back to client
        const responseHeaders = new Headers();

        // Forward X-Request-ID for debugging/audit tracking
        const requestId = response.headers.get('X-Request-ID');
        if (requestId) {
            responseHeaders.set('X-Request-ID', requestId);
        }

        if (process.env.NODE_ENV === 'development') {
            console.log('🔄 Proxying to Spring Boot:', {
                path: backendPath,
                ip: headers['X-Forwarded-For'] || headers['X-Real-IP'],
                userAgent: headers['User-Agent'],
                deviceId: headers['X-Device-ID'],
                hasAuth: !!headers['Authorization'],
            });
        }

        return NextResponse.json(data, {
            status: response.status,
            headers: responseHeaders,
        });
    } catch (error) {
        const handledError = handleServerError(error);
        return NextResponse.json(handledError, { status: handledError.statusCode });
    }
}

/**
 * Extract real client IP from Next.js request
 * Handles various proxy scenarios (Vercel, Cloudflare, etc.)
 */
function getClientIp(request: NextRequest): string {
    // Try X-Forwarded-For first (most common)
    const forwarded = request.headers.get('x-forwarded-for');
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }

    // Try X-Real-IP
    const realIp = request.headers.get('x-real-ip');
    if (realIp) {
        return realIp;
    }

    // Cloudflare specific
    const cfConnectingIp = request.headers.get('cf-connecting-ip');
    if (cfConnectingIp) {
        return cfConnectingIp;
    }

    // Vercel specific
    const vercelIp = request.headers.get('x-vercel-forwarded-for');
    if (vercelIp) {
        return vercelIp;
    }

    return 'unknown';
}