package com.rishan.guardianstack.core.exception;

// Base exception for verification issues
public class VerificationException extends RuntimeException {
    public VerificationException(String message) {
        super(message);
    }
}