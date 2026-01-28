// lib/api/proxy.ts
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { getBackendUrl } from '@/lib/api.client';
import { decryptToken, encryptToken } from '@/lib/api/crypto';
import { handleServerError } from '@/lib/api/error-handling';

interface ProxyOptions {
  requireAuth?: boolean;
  storeTokens?: boolean; // Changed from storeJwt to be clearer
}

export async function proxyToBackend(
  request: NextRequest,
  backendPath: string,
  options: ProxyOptions = {}
) {
  try {
    const { requireAuth = false, storeTokens = false } = options;
    const SPRING_BOOT_URL = getBackendUrl();
    
    // Build headers to forward to Spring Boot
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    // 1. Extract and forward Client IP
    const clientIp = getClientIp(request);
    if (clientIp && clientIp !== 'unknown') {
      headers['X-Forwarded-For'] = clientIp;
      headers['X-Real-IP'] = clientIp;
    }
    
    // 2. Extract and forward User-Agent (CRITICAL for device fingerprinting)
    const userAgent = request.headers.get('user-agent');
    if (userAgent) {
      headers['User-Agent'] = userAgent;
    }
    
    // 3. Extract and forward Device ID (CRITICAL for device fingerprinting)
    const deviceId = request.headers.get('x-device-id');
    if (deviceId) {
      headers['X-Device-ID'] = deviceId;
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

      // Decrypt JWT and add to Authorization header
      const jwtToken = decryptToken(encryptedJwt);
      headers['Authorization'] = `Bearer ${jwtToken}`;
    }

    // 5. Build URL with query parameters
    const backendUrl = buildBackendUrl(SPRING_BOOT_URL, backendPath, request);

    // 6. Get request body for POST/PUT/PATCH
    let body: string | undefined;
    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      try {
        const jsonBody = await request.json();
        body = JSON.stringify(jsonBody);
      } catch {
        body = undefined;
      }
    }

    // Debug logging in development
    if (process.env.NODE_ENV === 'development') {
      console.log('🔄 Proxying to Spring Boot:', {
        url: backendUrl,
        method: request.method,
        clientIp: headers['X-Forwarded-For'] || 'unknown',
        userAgent: headers['User-Agent'] || 'missing',
        deviceId: headers['X-Device-ID'] || 'missing',
        hasAuth: !!headers['Authorization'],
        hasBody: !!body,
      });
    }

    // Forward request to Spring Boot
    const response = await fetch(backendUrl, {
      method: request.method,
      headers,
      body,
    });

    const data = await response.json();

    // Store tokens if this is an authentication endpoint (login, signup, verify-otp, refresh)
    if (storeTokens && response.ok && data.success && data.data) {
      const cookieStore = await cookies();
      
      // Store JWT Token (encrypted, httpOnly: true)
      if (data.data.jwtToken) {
        const encryptedJwt = encryptToken(data.data.jwtToken);
        
        cookieStore.set('jwt_token', encryptedJwt, {
          httpOnly: true, // ✅ Browser JavaScript CANNOT read this
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          path: '/',
          maxAge: 60 * 15, // 15 minutes (adjust to match your JWT expiry)
        });
        
        if (process.env.NODE_ENV === 'development') {
          console.log('🔐 JWT token encrypted and stored in httpOnly cookie');
        }
      }
      
      // Store Refresh Token (encrypted, httpOnly: true)
      if (data.data.refreshToken) {
        const encryptedRefreshToken = encryptToken(data.data.refreshToken);
        
        cookieStore.set('refresh_token', encryptedRefreshToken, {
          httpOnly: true, // ✅ Browser JavaScript CANNOT read this
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          path: '/',
          maxAge: 60 * 60 * 24 * 30, // 30 days (adjust to match your refresh token expiry)
        });
        
        if (process.env.NODE_ENV === 'development') {
          console.log('🔐 Refresh token encrypted and stored in httpOnly cookie');
        }
      }
      
      // Generate CSRF Token (plain text, httpOnly: false)
      const csrfToken = crypto.randomUUID();
      cookieStore.set('XSRF-TOKEN', csrfToken, {
        httpOnly: false, // ✅ Browser JavaScript CAN read this (needed for CSRF protection)
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
      });
      
      if (process.env.NODE_ENV === 'development') {
        console.log('🛡️ CSRF token generated and stored (readable by browser JS)');
      }
      
      // Remove tokens from response body (keep them secret server-side)
      delete data.data.jwtToken;
      delete data.data.refreshToken;
    }

    // Forward important response headers back to client
    const responseHeaders = new Headers();
    const requestId = response.headers.get('X-Request-ID');
    if (requestId) {
      responseHeaders.set('X-Request-ID', requestId);
    }

    return NextResponse.json(data, { 
      status: response.status,
      headers: responseHeaders,
    });
  } catch (error) {
    console.error('❌ Proxy error:', error);
    const handledError = handleServerError(error);
    return NextResponse.json(handledError, { status: handledError.statusCode });
  }
}

/**
 * Build backend URL with query parameters
 * Copies all query params from the Next.js request to the Spring Boot URL
 */
function buildBackendUrl(
  baseUrl: string,
  backendPath: string,
  request: NextRequest
): string {
  const url = new URL(backendPath, baseUrl);
  
  // Copy all query parameters from Next.js request to Spring Boot URL
  request.nextUrl.searchParams.forEach((value, key) => {
    url.searchParams.append(key, value);
  });
  
  return url.toString();
}

/**
 * Extract real client IP from Next.js request
 * Handles various deployment scenarios (Vercel, Cloudflare, local)
 */
function getClientIp(request: NextRequest): string {
  // Try X-Forwarded-For first (most common with proxies)
  const forwarded = request.headers.get('x-forwarded-for');
  if (forwarded) {
    const ips = forwarded.split(',');
    return ips[0].trim();
  }
  
  const realIp = request.headers.get('x-real-ip');
  if (realIp) return realIp;
  
  const cfConnectingIp = request.headers.get('cf-connecting-ip');
  if (cfConnectingIp) return cfConnectingIp;
  
  const vercelIp = request.headers.get('x-vercel-forwarded-for');
  if (vercelIp) return vercelIp;
  
  // const remoteAddr = request.ip;
  // if (remoteAddr) return remoteAddr;
  
  return 'unknown';
}