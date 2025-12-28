import { ApiErrorResponse, ApiResponse } from "@/types/api.types";

export function createServerError<T = unknown>(
  message: string | string[],
  statusCode: number,
  data?: T | null,
  timestamp?: string,

): ApiErrorResponse<T> {
  return {
    success: false,
    message,
    statusCode,
    data: data ?? null,
    timestamp: timestamp || new Date().toISOString(),

  };
}

export function isServerError(error: unknown): error is ApiErrorResponse {
  return (
    typeof error === 'object' &&
    error !== null &&
    'success' in error &&
    error.success === false &&
    'message' in error &&
    'statusCode' in error &&
    'data' in error &&
    'timestamp' in error
  );
}

export function isServerSuccess<T = unknown>(
  response: unknown
): response is ApiResponse<T> {
  return (
    typeof response === 'object' &&
    response !== null &&
    'success' in response &&
    response.success === true &&
    'message' in response &&
    'data' in response
  );
}

export function handleServerError(error: unknown): ApiErrorResponse {
  const timestamp = new Date().toISOString();

  if (isServerError(error)) {
    return error;
  }

  if (typeof error === 'object' && error !== null) {
    const err = error as Record<string, unknown>;

    if ('statusCode' in err && 'message' in err) {
      return createServerError(
        err.message as string | string[],
        Number(err.statusCode),
        'data' in err ? (err.data as unknown) : null,
        timestamp,

      );
    }
  }

  if (error instanceof TypeError) {
    return createServerError(
      'Network error or server unreachable',
      503,
      null,
      timestamp
    );
  }

  return createServerError(
    error instanceof Error ? error.message : 'An unexpected error occurred',
    500,
    null,
    timestamp
  );
}