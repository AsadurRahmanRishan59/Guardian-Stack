package com.rishan.guardianstack.core.exception;

public class TokenAlreadyUsedException extends VerificationException {
    public TokenAlreadyUsedException(String message) {
        super(message);
    }
}