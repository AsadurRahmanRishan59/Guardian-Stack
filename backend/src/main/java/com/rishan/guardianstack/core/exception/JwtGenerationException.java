package com.rishan.guardianstack.core.exception;

public class JwtGenerationException extends RuntimeException {
    public JwtGenerationException(String message) {
        super(message);
    }
}