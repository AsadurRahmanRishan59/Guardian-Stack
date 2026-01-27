// app/api/auth/signup/route.ts
import { NextRequest } from 'next/server';
import { proxyToBackend } from '@/lib/api/proxy';

export async function POST(request: NextRequest) {
  return proxyToBackend(request, '/api/auth/public/signup', { storeJwt: false });
}

// app/api/auth/signup/route.ts
// import { NextRequest, NextResponse } from 'next/server';
// import { handleServerError } from '@/lib/api/error-handling';
// import { getBackendUrl } from '@/lib/api.client';

// export async function POST(request: NextRequest) {
//   try {
//     const body = await request.json();
//     const SPRING_BOOT_URL = getBackendUrl();
//     const userAgent = request.headers.get('user-agent') || 'unknown';
//     const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/signup`, {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/json',
//         'User-Agent': userAgent,
//       },

//       body: JSON.stringify(body),
//     });

//     const data = await response.json();
//     return NextResponse.json(data, { status: response.status });
//   } catch (error) {
//     const handledError = handleServerError(error);
//     return NextResponse.json(handledError, { status: handledError.statusCode });
//   }
// }