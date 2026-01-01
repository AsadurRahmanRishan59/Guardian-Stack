// app/api/auth/forgot-password/route.ts
import { getBackendUrl } from "@/lib/api.client";
import { handleServerError } from "@/lib/api/error-handling";
import { NextRequest, NextResponse } from "next/server";

export async function POST(request: NextRequest) {
    const SPRING_BOOT_URL = getBackendUrl();
    const { email } = await request.json();
    const params = new URLSearchParams({ email });
    try {
        const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/forgot-password?${params.toString()}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
        });


        const data = await response.json();
        return NextResponse.json(data, { status: response.status });

    } catch (error) {
        const handledError = handleServerError(error);
        return NextResponse.json(handledError, { status: handledError.statusCode });
    }
}