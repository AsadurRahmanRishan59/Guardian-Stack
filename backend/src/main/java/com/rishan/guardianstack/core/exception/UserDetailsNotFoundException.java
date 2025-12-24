package com.rishan.guardianstack.core.exception;


public class UserDetailsNotFoundException extends RuntimeException {
    public UserDetailsNotFoundException(String message) {
        super(message);
    }
}
