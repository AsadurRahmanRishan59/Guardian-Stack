// app/api/master-admin/audit/tariffs/motor/[tariffKey]/revision/[revisionNumber]/route.ts
import { NextRequest } from 'next/server';
import { proxyToBackend } from '@/lib/api/proxy';

interface RouteParams {
  params: Promise<{ tariffKey: string; revisionNumber: string }>;
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  const { tariffKey, revisionNumber } = await params;
  return proxyToBackend(
    request,
    `/api/master-admin/audit/tariffs/motor/${tariffKey}/revision/${revisionNumber}`,
    { requireAuth: true }
  );
}