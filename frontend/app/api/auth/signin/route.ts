// app/api/auth/signin/route.ts
import { NextRequest } from 'next/server';
import { proxyToBackend } from '@/lib/api/proxy';

export async function POST(request: NextRequest) {
  return proxyToBackend(request, '/api/auth/public/signin', { storeTokens: true });
}

// app/api/auth/signin/route.ts
// import { NextRequest, NextResponse } from 'next/server';
// import { cookies } from 'next/headers';
// import { handleServerError } from '@/lib/api/error-handling';
// import { encryptToken } from '@/lib/api/crypto';
// import { getBackendUrl } from '@/lib/api.client';

// export async function POST(request: NextRequest) {
//   try {
//     const body = await request.json();
//     const SPRING_BOOT_URL = getBackendUrl();
//     const userAgent = request.headers.get('user-agent') || 'unknown';
//     const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/signin`, {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/json',
//         'User-Agent': userAgent,
//       },
//       credentials: 'include',
//       body: JSON.stringify(body),
//     });

//     const data = await response.json();

//     if (response.ok && data.success) {
//       const jwtToken = data.data?.jwtToken;
//       const cookieStore = await cookies();

//       // 1. Set the JWT (Secure, private)
//       if (jwtToken) {
//         const encryptedJwt = encryptToken(jwtToken);
//         cookieStore.set('jwt_token', encryptedJwt, {
//           httpOnly: true,
//           // secure: true,
//           sameSite: 'lax',
//           path: '/',
//         });
//       }

//       // 2. Generate and Set XSRF-TOKEN (Readable by Browser JS)
//       const csrfToken = crypto.randomUUID();
//       cookieStore.set('XSRF-TOKEN', csrfToken, {
//         httpOnly: false, // CRITICAL: Must be false so the browser can read it
//         // secure: true,
//         sameSite: 'lax',
//         path: '/',
//       });

//       return NextResponse.json(data);
//     }
//     return NextResponse.json(data, { status: response.status });
//   } catch (error) {
//     const handledError = handleServerError(error);
//     return NextResponse.json(handledError, { status: handledError.statusCode });
//   }
// }

