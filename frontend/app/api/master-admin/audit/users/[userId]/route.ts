// app/api/master-admin/audit/users/[userId]/route.ts

import { NextRequest } from 'next/server';
import { proxyToBackend } from '@/lib/api/proxy';

export async function GET(request: NextRequest,
    context: { params: Promise<{ userId: string }> }) {
        const { userId } = await context.params;
  return proxyToBackend(request, `/api/master-admin/audit/users/${userId}`, { requireAuth: true });
}
