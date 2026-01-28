// app/api/auth/logout/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { getBackendUrl } from '@/lib/api.client';
import { decryptToken } from '@/lib/api/crypto';
import { handleServerError } from '@/lib/api/error-handling';

export async function POST(request: NextRequest) {
  try {
    const cookieStore = await cookies();
    
    // Get encrypted tokens from cookies
    const encryptedJwt = cookieStore.get('jwt_token')?.value;
    const encryptedRefreshToken = cookieStore.get('refresh_token')?.value;
    
    if (!encryptedJwt || !encryptedRefreshToken) {
      // Clear any remaining cookies
      cookieStore.delete('jwt_token');
      cookieStore.delete('refresh_token');
      cookieStore.delete('XSRF-TOKEN');
      
      return NextResponse.json({
        success: true,
        message: 'Already logged out'
      });
    }
    
    // Decrypt tokens
    const jwtToken = decryptToken(encryptedJwt);
    const refreshToken = decryptToken(encryptedRefreshToken);
    
    const SPRING_BOOT_URL = getBackendUrl();
    
    // Forward headers
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${jwtToken}`,
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
    
    // Call Spring Boot logout endpoint
    const response = await fetch(`${SPRING_BOOT_URL}/api/auth/logout`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ refreshToken }),
    });
    
    // Always clear cookies, even if backend call fails
    cookieStore.delete('jwt_token');
    cookieStore.delete('refresh_token');
    cookieStore.delete('XSRF-TOKEN');
    
    const data = await response.json();
    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error('Logout error:', error);
    
    // Clear cookies even on error
    const cookieStore = await cookies();
    cookieStore.delete('jwt_token');
    cookieStore.delete('refresh_token');
    cookieStore.delete('XSRF-TOKEN');
    
    const handledError = handleServerError(error);
    return NextResponse.json(handledError, { status: handledError.statusCode });
  }
}