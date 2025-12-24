package com.rishan.guardianstack.core.exception;

import lombok.Getter;

import java.util.Map;

/**
 * Exception for handling multiple field validation errors
 */
@Getter
public class MultipleFieldValidationException extends RuntimeException {

    private final Map<String, String> fieldErrors;

    public MultipleFieldValidationException(Map<String, String> fieldErrors) {
        this.fieldErrors = fieldErrors;
    }

    public MultipleFieldValidationException(String message, Map<String, String> fieldErrors) {
        super(message);
        this.fieldErrors = fieldErrors;
    }

}