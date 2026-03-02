// app/api/master-admin/audit/users/[userId]/revision/[revisionNumber]/route.ts

import { NextRequest } from 'next/server';
import { proxyToBackend } from '@/lib/api/proxy';

export async function GET(
    request: NextRequest,
    context: { params: Promise<{ userId: string; revisionNumber: string }> }
) {
    // 1. Await both dynamic segments from the params Promise
    const { userId, revisionNumber } = await context.params;

    // 2. Pass the extracted variables into the backend URL string
    return proxyToBackend(
        request, 
        `/api/master-admin/audit/users/${userId}/revision/${revisionNumber}`, 
        { requireAuth: true }
    );
}