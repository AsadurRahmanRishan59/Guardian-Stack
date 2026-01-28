// app/api/auth/reset-password/route.ts
import { NextRequest } from 'next/server';
import { proxyToBackend } from '@/lib/api/proxy';

export async function POST(request: NextRequest) {
    return proxyToBackend(request, '/api/auth/public/reset-password');
}

// app/api/auth/reset-password/route.ts
// import { getBackendUrl } from "@/lib/api.client";
// import { handleServerError } from "@/lib/api/error-handling";
// import { NextRequest, NextResponse } from "next/server";

// export async function POST(request: NextRequest) {
//     const SPRING_BOOT_URL = getBackendUrl();
//     const body = await request.json();
//     const userAgent = request.headers.get('user-agent') || 'unknown';
//     try {
//         const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/reset-password`, {
//             method: 'POST',
//             headers: {
//               'Content-Type': 'application/json',
//               'User-Agent': userAgent,
//             },
//             body: JSON.stringify(body)
//         },
//         );

//         const data = await response.json();
//         return NextResponse.json(data, { status: response.status });

//     } catch (error) {
//         const handledError = handleServerError(error);
//         return NextResponse.json(handledError, { status: handledError.statusCode });
//     }
// }