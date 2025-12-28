import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';

export async function POST() {
  const cookieStore = await cookies();

  // Delete auth cookies
  cookieStore.delete('jwt_token');
  cookieStore.delete('XSRF-TOKEN');

  return NextResponse.json({
    success: true,
    message: 'Logged out successfully',
    data: null,
    timestamp: new Date().toISOString(),
  });
}