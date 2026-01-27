// app/api/auth/refresh/route.ts
import { NextRequest } from 'next/server';
import { proxyToBackend } from '@/lib/api/proxy';

export async function POST(request: NextRequest) {
  return proxyToBackend(request, '/api/auth/public/refresh', { storeJwt: true });
}