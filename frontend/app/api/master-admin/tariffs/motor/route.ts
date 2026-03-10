// app/api/master-admin/tariffs/motor/route.ts

import { NextRequest } from 'next/server';
import { proxyToBackend } from '@/lib/api/proxy';

export async function GET(request: NextRequest) {
  return proxyToBackend(request, '/api/master-admin/tariff/motor', { requireAuth: true });
}

export async function POST(request: NextRequest) {
  return proxyToBackend(request, '/api/master-admin/tariff/motor', { requireAuth: true });
}
