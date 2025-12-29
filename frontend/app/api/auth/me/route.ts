
// app/api/auth/me/route.ts
import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { getBackendUrl } from '@/lib/api.utils';
import { handleServerError } from '@/lib/api/error-handling';
import { decryptToken } from '@/lib/api/crypto';

export async function GET() {
  try {
    const SPRING_BOOT_URL = getBackendUrl();
    const encryptedJwt = (await cookies()).get('jwt_token')?.value;

    if (!encryptedJwt) {
      return NextResponse.json(
        {
          success: false,
          message: 'Not authenticated',
          statusCode: 401,
          data: null,
          timestamp: new Date().toISOString(),
        },
        { status: 401 }
      );
    }
    const rawJwt = decryptToken(encryptedJwt);

    const headers: HeadersInit = {
      'Authorization': `Bearer ${rawJwt}`,
    };

    const response = await fetch(`${SPRING_BOOT_URL}/api/auth/me`, {
      method: 'GET',
      headers,
    });

    const data = await response.json();

    if (response.status === 401) {
      const cookieStore = await cookies();
      cookieStore.delete('jwt_token');
      cookieStore.delete('XSRF-TOKEN');
    }

    return NextResponse.json(data, { status: response.status });

  } catch (error) {
    const handledError = handleServerError(error);
    return NextResponse.json(handledError, { status: handledError.statusCode });
  }
}