// app/api/auth/me/route.ts
import { NextRequest } from 'next/server';
import { proxyToBackend } from '@/lib/api/proxy';

export async function GET(request: NextRequest) {
  return proxyToBackend(request, '/api/auth/me', { requireAuth: true });
}

// app/api/auth/me/route.ts
// import { NextResponse } from 'next/server';
// import { cookies,headers } from 'next/headers';
// import { handleServerError } from '@/lib/api/error-handling';
// import { decryptToken } from '@/lib/api/crypto';
// import { getBackendUrl } from '@/lib/api.client';

// export async function GET() {
//   try {
//     const SPRING_BOOT_URL = getBackendUrl();
//     const encryptedJwt = (await cookies()).get('jwt_token')?.value;

//     const headerList = await headers();
//     const userAgent = headerList.get('user-agent') || 'unknown';

//     if (!encryptedJwt) {
//       return NextResponse.json(
//         {
//           success: false,
//           message: 'Not authenticated',
//           statusCode: 401,
//           data: null,
//           timestamp: new Date().toISOString(),
//         },
//         { status: 401 }
//       );
//     }
//     const rawJwt = decryptToken(encryptedJwt);

//     const backendHeaders: HeadersInit = {
//       'Authorization': `Bearer ${rawJwt}`,
//       'User-Agent': userAgent,
//     };

//     const response = await fetch(`${SPRING_BOOT_URL}/api/auth/me`, {
//       method: 'GET',
//       headers: backendHeaders,
//     });

//     const data = await response.json();

//     if (response.status === 401) {
//       const cookieStore = await cookies();
//       cookieStore.delete('jwt_token');
//       cookieStore.delete('XSRF-TOKEN');
//     }

//     return NextResponse.json(data, { status: response.status });

//   } catch (error) {
//     const handledError = handleServerError(error);
//     return NextResponse.json(handledError, { status: handledError.statusCode });
//   }
// }