package com.rishan.guardianstack.auth.service;

import com.rishan.guardianstack.auth.model.User;
import jakarta.servlet.http.HttpServletRequest;

public interface VerificationService {
    String createEmailVerificationToken(User user);
    User verifyEmailVerificationToken(String email, String otp);
    User verifyPasswordResetToken(String email, String otp);
    String createPasswordResetToken(User user);
}
