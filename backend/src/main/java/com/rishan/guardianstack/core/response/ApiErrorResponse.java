package com.rishan.guardianstack.core.response;

import java.time.LocalDateTime;

public record ApiErrorResponse<T>(boolean success, String message, int statusCode, T data,
                                  LocalDateTime timestamp) {
}
