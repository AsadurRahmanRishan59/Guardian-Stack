// app/api/auth/refresh/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { getBackendUrl } from '@/lib/api.client';
import { decryptToken, encryptToken } from '@/lib/api/crypto';
import { handleServerError } from '@/lib/api/error-handling';

export async function POST(request: NextRequest) {
  try {
    const cookieStore = await cookies();
    
    // Get encrypted refresh token from cookie
    const encryptedRefreshToken = cookieStore.get('refresh_token')?.value;
    
    if (!encryptedRefreshToken) {
      return NextResponse.json(
        { success: false, message: 'No refresh token found' },
        { status: 401 }
      );
    }
    
    // Decrypt refresh token
    const refreshToken = decryptToken(encryptedRefreshToken);
    
    const SPRING_BOOT_URL = getBackendUrl();
    
    // Forward headers
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    
    const userAgent = request.headers.get('user-agent');
    if (userAgent) headers['User-Agent'] = userAgent;
    
    const deviceId = request.headers.get('x-device-id');
    if (deviceId) headers['X-Device-ID'] = deviceId;
    
    const clientIp = request.headers.get('x-forwarded-for');
    if (clientIp) {
      headers['X-Forwarded-For'] = clientIp.split(',')[0].trim();
      headers['X-Real-IP'] = clientIp.split(',')[0].trim();
    }
    
    // Call Spring Boot refresh endpoint
    const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/refresh`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ refreshToken }),
    });
    
    const data = await response.json();
    
    if (response.ok && data.success && data.data) {
      // Store new JWT token (encrypted, httpOnly)
      if (data.data.jwtToken) {
        const encryptedJwt = encryptToken(data.data.jwtToken);
        cookieStore.set('jwt_token', encryptedJwt, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          path: '/',
          maxAge: 60 * 15,
        });
      }
      
      // Store new refresh token if rotated (encrypted, httpOnly)
      if (data.data.refreshToken) {
        const encryptedNewRefreshToken = encryptToken(data.data.refreshToken);
        cookieStore.set('refresh_token', encryptedNewRefreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          path: '/',
          maxAge: 60 * 60 * 24 * 30,
        });
      }
      
      // Remove tokens from response
      delete data.data.jwtToken;
      delete data.data.refreshToken;
    }
    
    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error('Token refresh error:', error);
    const handledError = handleServerError(error);
    return NextResponse.json(handledError, { status: handledError.statusCode });
  }
}