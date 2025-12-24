package com.rishan.guardianstack.core.util;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@Component
public class EmailPolicyValidator {

    private static final String EMAIL_REGEX = "^[A-Za-z0-9+_.-]+@(.+)$";
    private static final List<String> BLACKLISTED_DOMAINS = List.of("mailinator.com", "trashmail.com", "tempmail.com");

    public List<String> validate(String email) {
        List<String> errors = new ArrayList<>();

        if (email == null || email.isBlank()) {
            return errors; // Handled by DTO if required, or ignored if optional
        }

        // 1. Basic Format
        if (!Pattern.compile(EMAIL_REGEX).matcher(email).matches()) {
            errors.add("Email format is invalid.");
        }

        // 2. Block Disposable Emails (Common in fraud)
        String domain = email.substring(email.indexOf("@") + 1).toLowerCase();
        if (BLACKLISTED_DOMAINS.contains(domain)) {
            errors.add("Disposable email addresses are not allowed for insurance policies.");
        }

        return errors;
    }
}