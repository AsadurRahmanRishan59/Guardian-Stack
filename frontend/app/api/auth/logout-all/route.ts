import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { getBackendUrl } from '@/lib/api.client';
import { decryptToken } from '@/lib/api/crypto';
import { handleServerError } from '@/lib/api/error-handling';

export async function POST(request: NextRequest) {
  try {
    const cookieStore = await cookies();
    
    // 1. Get encrypted JWT
    const encryptedJwt = cookieStore.get('jwt_token')?.value;
    
    if (!encryptedJwt) {
      // If no session exists, just clear any stray cookies
      cookieStore.delete('jwt_token');
      cookieStore.delete('refresh_token');
      cookieStore.delete('XSRF-TOKEN');
      
      return NextResponse.json({
        success: true,
        message: 'No active session found'
      });
    }
    
    // 2. Decrypt JWT for the Authorization header
    const jwtToken = decryptToken(encryptedJwt);
    const SPRING_BOOT_URL = getBackendUrl();
    
    // 3. Prepare headers (Spring Boot uses @AuthenticationPrincipal from the Bearer token)
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${jwtToken}`,
    };
    
    // Forward audit headers so Spring Boot knows which device triggered the global logout
    const userAgent = request.headers.get('user-agent');
    if (userAgent) headers['User-Agent'] = userAgent;
    
    const clientIp = request.headers.get('x-forwarded-for');
    if (clientIp) {
      headers['X-Forwarded-For'] = clientIp.split(',')[0].trim();
      headers['X-Real-IP'] = clientIp.split(',')[0].trim();
    }
    
    // 4. Call Spring Boot logout-all
    // Note: No body required as per your Java Controller
    const response = await fetch(`${SPRING_BOOT_URL}/api/auth/logout-all`, {
      method: 'POST',
      headers,
    });
    
    // 5. CRITICAL: Clear all local cookies
    cookieStore.delete('jwt_token');
    cookieStore.delete('refresh_token');
    cookieStore.delete('XSRF-TOKEN');
    
    const data = await response.json();
    return NextResponse.json(data, { status: response.status });

  } catch (error) {
    console.error('Logout-all error:', error);
    
    // Force clear cookies even if the backend call fails
    const cookieStore = await cookies();
    cookieStore.delete('jwt_token');
    cookieStore.delete('refresh_token');
    cookieStore.delete('XSRF-TOKEN');
    
    const handledError = handleServerError(error);
    return NextResponse.json(handledError, { status: handledError.statusCode });
  }
}