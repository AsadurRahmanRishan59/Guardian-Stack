package com.rishan.guardianstack.core.exception;

/**
 * Exception thrown when a file cannot be accessed or read
 */
public class FileAccessException extends RuntimeException {

    public FileAccessException(String message) {
        super(message);
    }

    public FileAccessException(String message, Throwable cause) {
        super(message, cause);
    }
}