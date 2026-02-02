// app/api/master-admin/user/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';

import { handleServerError } from '@/lib/api/error-handling';
import { getBackendUrl } from '@/lib/api.client';
import { proxyToBackend } from '@/lib/api/proxy';


export async function GET(request: NextRequest) {
  return proxyToBackend(request, '/api/masteradmin/users', { requireAuth: true });
}



// // GET - Get All Users
// export async function GET(request: NextRequest) {
//     const SPRING_BOOT_URL = getBackendUrl();
//     try {
//         // Check authentication
//         if (!checkAuth()) {
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

//         const headers = await getAuthHeaders(request, false);

//         // Get query parameters
//         const searchParams = request.nextUrl.searchParams;
//         const queryString = searchParams.toString();

//         // Forward request to Spring Boot
//         const url = `${SPRING_BOOT_URL}/api/admin/user${queryString ? `?${queryString}` : ''}`;
//         const response = await fetch(url, {
//             method: 'GET',
//             headers,
//         });

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



// POST - Create User
export async function POST(request: NextRequest) {
    const SPRING_BOOT_URL = getBackendUrl();
    try {
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

        const headers = await getAuthHeaders(request, true);
        const body = await request.json();

        // Forward request to Spring Boot
        const response = await fetch(`${SPRING_BOOT_URL}/api/admin/user`, {
            method: 'POST',
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
async function getAuthHeaders(request: NextRequest, nonGet: boolean): Promise<HeadersInit> {
    const jwtToken = (await cookies()).get('jwt_token')?.value;
    const xsrfToken = (await cookies()).get('XSRF-TOKEN')?.value;
    const userAgent = request.headers.get('user-agent') || 'unknown';

    const headers: HeadersInit = {
        'Content-Type': 'application/json',
        'User-Agent': userAgent,
    };

    // Add JWT token
    if (jwtToken) {
        headers['Authorization'] = `Bearer ${jwtToken}`;
    }

    // Add XSRF token
    if (xsrfToken && nonGet) {
        headers['X-XSRF-TOKEN'] = xsrfToken;
    }

    return headers;
}

// Check if user is authenticated
async function checkAuth(): Promise<boolean> {
    const jwtToken = (await cookies()).get('jwt_token')?.value;
    return !!jwtToken;
}
