package com.rishan.guardianstack.core.exception;

public class MustChangePasswordException extends RuntimeException {
    private final String email;

    public MustChangePasswordException(String message, String email) {
        super(message);
        this.email = email;
    }

    public String getEmail() {
        return email;
    }
}