// app/api/master-admin/audit/users/route.ts

import { NextRequest } from 'next/server';
import { proxyToBackend } from '@/lib/api/proxy';

export async function GET(request: NextRequest) {
  return proxyToBackend(request, '/api/master-admin/audit/users', { requireAuth: true });
}

