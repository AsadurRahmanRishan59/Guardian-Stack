package com.rishan.guardianstack.core.exception;

import java.time.LocalDateTime;

public class AccountExpiredException extends RuntimeException {
    private final LocalDateTime expiredOn;

    public AccountExpiredException(String message, LocalDateTime expiredOn) {
        super(message);
        this.expiredOn = expiredOn;
    }

    public LocalDateTime getExpiredOn() {
        return expiredOn;
    }
}