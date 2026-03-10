// app/api/master-admin/tariffs/motor/hierarchy/route.ts

import { NextRequest } from 'next/server';
import { proxyToBackend } from '@/lib/api/proxy';

export async function GET(request: NextRequest) {
  return proxyToBackend(request, '/api/tariff/motor/hierarchy', { requireAuth: true });
}
