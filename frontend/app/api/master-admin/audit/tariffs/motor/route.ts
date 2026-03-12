// app/api/master-admin/audit/tariffs/motor/route.ts
import { NextRequest } from 'next/server';
import { proxyToBackend } from '@/lib/api/proxy';

export async function GET(request: NextRequest) {
  return proxyToBackend(request, '/api/master-admin/audit/tariffs/motor', { requireAuth: true });
}