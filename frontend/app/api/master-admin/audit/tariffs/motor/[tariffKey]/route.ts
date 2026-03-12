// app/api/master-admin/audit/tariffs/motor/[tariffKey]/route.ts
import { NextRequest } from 'next/server';
import { proxyToBackend } from '@/lib/api/proxy';

interface RouteParams {
  params: Promise<{ tariffKey: string }>;
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  const { tariffKey } = await params;
  return proxyToBackend(
    request,
    `/api/master-admin/audit/tariffs/motor/${tariffKey}`,
    { requireAuth: true }
  );
}