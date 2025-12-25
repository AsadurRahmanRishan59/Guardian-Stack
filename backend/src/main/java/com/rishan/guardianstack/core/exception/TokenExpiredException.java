package com.rishan.guardianstack.core.exception;

// Specific subtypes
public class TokenExpiredException extends VerificationException {
    public TokenExpiredException(String message) {
        super(message);
    }
}