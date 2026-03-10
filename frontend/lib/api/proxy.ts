// lib/api/proxy.ts
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { getBackendUrl } from '@/lib/api.client';
import { decryptToken, encryptToken } from '@/lib/api/crypto';
import { handleServerError } from '@/lib/api/error-handling';

interface ProxyOptions {
  requireAuth?: boolean;
  storeTokens?: boolean;
}

export async function proxyToBackend(
  request: NextRequest,
  backendPath: string,
  options: ProxyOptions = {}
) {
  try {
    const { requireAuth = false, storeTokens = false } = options;
    const SPRING_BOOT_URL = getBackendUrl();

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    // 1. Client IP
    const clientIp = getClientIp(request);
    if (clientIp && clientIp !== 'unknown') {
      headers['X-Forwarded-For'] = clientIp;
      headers['X-Real-IP'] = clientIp;
    }

    // 2. User-Agent
    const userAgent = request.headers.get('user-agent');
    if (userAgent) {
      headers['User-Agent'] = userAgent;
    }

    // 3. Device ID
    const deviceId = request.headers.get('x-device-id');
    if (deviceId) {
      headers['X-Device-ID'] = deviceId;
    }

    // 4. JWT
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

    // 5. Build URL with query parameters
    const backendUrl = buildBackendUrl(SPRING_BOOT_URL, backendPath, request);

    // 6. Body — POST/PUT/PATCH carry a JSON body.
    //          DELETE may optionally carry one (e.g. bulk-delete with IDs).
    //          GET/HEAD never have a body.
    let body: string | undefined;
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) {
      try {
        const jsonBody = await request.json();
        body = JSON.stringify(jsonBody);
      } catch {
        // DELETE with no body is valid — leave body undefined
        body = undefined;
      }
    }

    if (process.env.NODE_ENV === 'development') {
      console.log('🔄 Proxying to Spring Boot:', {
        url:       backendUrl,
        method:    request.method,
        clientIp:  headers['X-Forwarded-For'] || 'unknown',
        userAgent: headers['User-Agent']       || 'missing',
        deviceId:  headers['X-Device-ID']      || 'missing',
        hasAuth:   !!headers['Authorization'],
        hasBody:   !!body,
      });
    }

    const response = await fetch(backendUrl, {
      method:  request.method,
      headers,
      body,
    });

    // 204 No Content — Spring Boot returns no body on successful DELETE.
    // Calling response.json() on an empty body would throw, so short-circuit.
    if (response.status === 204) {
      return new NextResponse(null, { status: 204 });
    }

    const data = await response.json();

    // Store tokens (login / signup / verify-otp / refresh)
    if (storeTokens && response.ok && data.success && data.data) {
      const cookieStore = await cookies();

      if (data.data.jwtToken) {
        const encryptedJwt = encryptToken(data.data.jwtToken);
        cookieStore.set('jwt_token', encryptedJwt, {
          httpOnly: true,
          secure:   process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          path:     '/',
          maxAge:   60 * 15,
        });
        if (process.env.NODE_ENV === 'development') {
          console.log('🔐 JWT token encrypted and stored in httpOnly cookie');
        }
      }

      if (data.data.refreshToken) {
        const encryptedRefreshToken = encryptToken(data.data.refreshToken);
        cookieStore.set('refresh_token', encryptedRefreshToken, {
          httpOnly: true,
          secure:   process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          path:     '/',
          maxAge:   60 * 60 * 24 * 30,
        });
        if (process.env.NODE_ENV === 'development') {
          console.log('🔐 Refresh token encrypted and stored in httpOnly cookie');
        }
      }

      const csrfToken = crypto.randomUUID();
      cookieStore.set('XSRF-TOKEN', csrfToken, {
        httpOnly: false,
        secure:   process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path:     '/',
      });
      if (process.env.NODE_ENV === 'development') {
        console.log('🛡️ CSRF token generated and stored');
      }

      delete data.data.jwtToken;
      delete data.data.refreshToken;
    }

    const responseHeaders = new Headers();
    const requestId = response.headers.get('X-Request-ID');
    if (requestId) responseHeaders.set('X-Request-ID', requestId);

    return NextResponse.json(data, {
      status:  response.status,
      headers: responseHeaders,
    });
  } catch (error) {
    console.error('❌ Proxy error:', error);
    const handledError = handleServerError(error);
    return NextResponse.json(handledError, { status: handledError.statusCode });
  }
}

function buildBackendUrl(
  baseUrl: string,
  backendPath: string,
  request: NextRequest
): string {
  const url = new URL(backendPath, baseUrl);
  request.nextUrl.searchParams.forEach((value, key) => {
    url.searchParams.append(key, value);
  });
  return url.toString();
}

function getClientIp(request: NextRequest): string {
  const forwarded = request.headers.get('x-forwarded-for');
  if (forwarded) return forwarded.split(',')[0].trim();

  const realIp = request.headers.get('x-real-ip');
  if (realIp) return realIp;

  const cfIp = request.headers.get('cf-connecting-ip');
  if (cfIp) return cfIp;

  const vercelIp = request.headers.get('x-vercel-forwarded-for');
  if (vercelIp) return vercelIp;

  return 'unknown';
}