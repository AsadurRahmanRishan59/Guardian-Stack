// app/api/auth/signup/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { handleServerError } from '@/lib/api/error-handling';
import { getBackendUrl } from '@/lib/api.client';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const SPRING_BOOT_URL = getBackendUrl();
    const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/signup`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },

      body: JSON.stringify(body),
    });

    const data = await response.json();
    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    const handledError = handleServerError(error);
    return NextResponse.json(handledError, { status: handledError.statusCode });
  }
}