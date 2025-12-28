// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
    const { method, nextUrl, cookies, headers } = request;

    // 1. Only protect API routes
    // 2. Skip GET/HEAD/OPTIONS as they are usually safe
    // 3. Skip the login route (since that's where the token is issued)
    const isApiAction = nextUrl.pathname.startsWith('/api/') && 
                        !['GET', 'HEAD', 'OPTIONS'].includes(method) &&
                        !nextUrl.pathname.includes('/api/auth/login');

    if (isApiAction) {
        const csrfCookie = cookies.get('XSRF-TOKEN')?.value;
        const csrfHeader = headers.get('x-xsrf-token');

        // Validation: Header must exist and match Cookie
        if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
            return NextResponse.json(
                { success: false, message: 'Invalid or missing CSRF token' },
                { status: 403 }
            );
        }
    }

    return NextResponse.next();
}

// Ensure middleware only runs on API routes for performance
export const config = {
    matcher: '/api/:path*',
};