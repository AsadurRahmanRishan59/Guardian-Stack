// app/api/master-admin/user/[userId]/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';

import { handleServerError } from '@/lib/api/error-handling';
import { getBackendUrl } from '@/lib/api.client';
import { proxyToBackend } from '@/lib/api/proxy';


export async function GET(request: NextRequest,
    context: { params: Promise<{ userId: string }> }) {
        const { userId } = await context.params;
  return proxyToBackend(request, `/api/masteradmin/users/${userId}`, { requireAuth: true });
}

// // GET - Get User by ID
// export async function GET(
//     request: NextRequest,
//     context: { params: Promise<{ userId: string }> }
// ) {
//     try {
//         const SPRING_BOOT_URL = getBackendUrl();
//         const { userId } = await context.params;

//         // Check authentication
//         if (!(await checkAuth())) {
//             return NextResponse.json(
//                 {
//                     success: false,
//                     message: 'Not authenticated',
//                     statusCode: 401,
//                     data: null,
//                     timestamp: new Date().toISOString(),
//                 },
//                 { status: 401 }
//             );
//         }

//         const headers = await getAuthHeaders(request);

//         const response = await fetch(
//             `${SPRING_BOOT_URL}/api/admin/user/${userId}`,
//             {
//                 method: 'GET',
//                 headers,
//             }
//         );

//         const data = await response.json();

//         // If unauthorized, clear cookies
//         if (response.status === 401) {
//             (await cookies()).delete('jwt_token');
//             (await cookies()).delete('XSRF-TOKEN');
//         }

//         return NextResponse.json(data, { status: response.status });
//     } catch (error) {
//         const handledError = handleServerError(error);
//         return NextResponse.json(handledError, { status: handledError.statusCode });
//     }
// }

// PUT - Update User by id
export async function PUT(
    request: NextRequest,
    context: { params: Promise<{ userId: string }> }
) {
    try {
        const SPRING_BOOT_URL = getBackendUrl();
        const { userId } = await context.params;

        // Check authentication
        if (!(await checkAuth())) {
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
        const headers = await getAuthHeaders(request);
        console.log('Headers being sent to Spring Boot:', headers);
        const body = await request.json();

        // Forward request to Spring Boot
        const response = await fetch(`${SPRING_BOOT_URL}/api/admin/user/${userId}`, {
            method: 'PUT',
            headers,
            body: JSON.stringify(body),
        });

        const data = await response.json();

        // If unauthorized, clear cookies
        if (response.status === 401) {
            (await cookies()).delete('jwt_token');
            (await cookies()).delete('XSRF-TOKEN');
        }

        return NextResponse.json(data, { status: response.status });
    } catch (error) {
        const handledError = handleServerError(error);
        return NextResponse.json(handledError, { status: handledError.statusCode });
    }
}

// Helper function to get auth headers with JWT and XSRF tokens
async function getAuthHeaders(request: NextRequest): Promise<HeadersInit> {
    const jwtToken = (await cookies()).get('jwt_token')?.value;
    const userAgent = request.headers.get('user-agent') || 'unknown';
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${jwtToken}`,
        'User-Agent': userAgent,
    };
}

// Check if user is authenticated
async function checkAuth(): Promise<boolean> {
    const jwtToken = (await cookies()).get('jwt_token')?.value;
    return !!jwtToken;
}
