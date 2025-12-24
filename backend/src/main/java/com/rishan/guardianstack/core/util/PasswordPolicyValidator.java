package com.rishan.guardianstack.core.util;

import org.passay.*;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@Component
public class PasswordPolicyValidator {

    public List<String> validate(String password, String username) {
        PasswordValidator validator = new PasswordValidator(Arrays.asList(
                new LengthRule(8, 120),                       // Length: 8-120
                new CharacterRule(EnglishCharacterData.UpperCase, 1), // At least one upper
                new CharacterRule(EnglishCharacterData.LowerCase, 1), // At least one lower
                new CharacterRule(EnglishCharacterData.Digit, 1),     // At least one digit
                new CharacterRule(EnglishCharacterData.Special, 1),   // At least one symbol
                new IllegalSequenceRule(EnglishSequenceData.Alphabetical, 5, false), // No "abcde"
                new UsernameRule(), // Password cannot contain the username
                new WhitespaceRule() // No spaces allowed
        ));
// IMPORTANT: You must set the Username in the PasswordData object
        PasswordData passwordData = new PasswordData(password);
        passwordData.setUsername(username);

        RuleResult result = validator.validate(passwordData);
        if (result.isValid()) {
            return List.of(); // Success
        }

        // Returns human-readable errors like "Password must contain a digit"
        return validator.getMessages(result);
    }
}