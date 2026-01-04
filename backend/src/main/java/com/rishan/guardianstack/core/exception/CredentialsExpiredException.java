package com.rishan.guardianstack.core.exception;

import java.time.LocalDateTime;

public class CredentialsExpiredException extends RuntimeException {
    private final LocalDateTime expiredOn;

    public CredentialsExpiredException(String message, LocalDateTime expiredOn) {
        super(message);
        this.expiredOn = expiredOn;
    }

    public LocalDateTime getExpiredOn() {
        return expiredOn;
    }
}