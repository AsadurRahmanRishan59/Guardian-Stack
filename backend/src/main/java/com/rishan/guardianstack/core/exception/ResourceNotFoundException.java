package com.rishan.guardianstack.core.exception;

import lombok.Getter;

/**
 * Exception thrown when a requested resource is not found
 */
@Getter
public class ResourceNotFoundException extends RuntimeException {

    private String fieldName;

    public ResourceNotFoundException(String message) {
        super(message);
    }

    public ResourceNotFoundException(String message, String fieldName) {
        super(message);
        this.fieldName = fieldName;
    }

    public ResourceNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}