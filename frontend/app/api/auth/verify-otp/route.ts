// app/api/auth/verify-otp/route.ts
import { getBackendUrl } from "@/lib/api.client";
import { encryptToken } from "@/lib/api/crypto";
import { handleServerError } from "@/lib/api/error-handling";
import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";

export async function POST(request: NextRequest) {
  try {

    const SPRING_BOOT_URL = getBackendUrl();
    const { email, otp } = await request.json();

    // Use URLSearchParams to safely encode the query parameters
    const params = new URLSearchParams({ email, otp });

    // 1. Call the Spring Boot Endpoint
    const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/verify-otp?${params.toString()}`, {
      method: "POST",
      headers: {
        'Content-Type': 'application/json',
      },
    });

    const data = await response.json();

    if (response.ok && data.success) {
      const jwtToken = data.data?.jwtToken;
      const cookieStore = await cookies();

      // 1. Set the JWT (Secure, private)
      if (jwtToken) {
        const encryptedJwt = encryptToken(jwtToken);
        cookieStore.set('jwt_token', encryptedJwt, {
          httpOnly: true,
          // secure: true,
          sameSite: 'lax',
          path: '/',
        });
      }

      // 2. Generate and Set XSRF-TOKEN (Readable by Browser JS)
      const csrfToken = crypto.randomUUID();
      cookieStore.set('XSRF-TOKEN', csrfToken, {
        httpOnly: false, // CRITICAL: Must be false so the browser can read it
        // secure: true,
        sameSite: 'lax',
        path: '/',
      });
      return NextResponse.json(data);
    }
    return NextResponse.json(data, { status: response.status });

  } catch (error) {
    const handledError = handleServerError(error);
    return NextResponse.json(handledError, { status: handledError.statusCode });
  }
}