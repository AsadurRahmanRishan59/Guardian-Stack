// app/api/auth/logout-all/route.ts
import { NextRequest } from 'next/server';
import { cookies } from 'next/headers';
import { proxyToBackend } from '@/lib/api/proxy';

export async function POST(request: NextRequest) {
  const response = await proxyToBackend(request, '/api/auth/logout-all', { 
    requireAuth: true 
  });
  
  // Clear cookies on successful logout
  if (response.status === 200) {
    const cookieStore = await cookies();
    cookieStore.delete('jwt_token');
    cookieStore.delete('XSRF-TOKEN');
  }
  
  return response;
}