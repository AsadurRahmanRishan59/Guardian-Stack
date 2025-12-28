// app/api/admin/roles/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { getBackendUrl } from '@/lib/api.utils';
import { handleServerError } from '@/lib/api/error-handling';

// GET - Get All Roles
export async function GET(request: NextRequest) {
    const SPRING_BOOT_URL = getBackendUrl();
    try {
        // Check authentication
        if (!checkAuth()) {
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

        const headers = await getAuthHeaders(false);

        // Get query parameters
        const searchParams = request.nextUrl.searchParams;
        const queryString = searchParams.toString();

        // Forward request to Spring Boot
        const url = `${SPRING_BOOT_URL}/api/admin/roles${queryString ? `?${queryString}` : ''}`;
        const response = await fetch(url, {
            method: 'GET',
            headers,
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
async function getAuthHeaders(nonGet: boolean): Promise<HeadersInit> {
    const jwtToken = (await cookies()).get('jwt_token')?.value;
    const xsrfToken = (await cookies()).get('XSRF-TOKEN')?.value;

    const headers: HeadersInit = {
        'Content-Type': 'application/json',
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
