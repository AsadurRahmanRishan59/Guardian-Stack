package com.rishan.guardianstack.auth.service;

import com.rishan.guardianstack.auth.model.User;
import jakarta.servlet.http.HttpServletRequest;

public interface VerificationService {
    String createToken(User user);
    User verifyToken(String email, String otp, HttpServletRequest httpRequest);
    String createPasswordResetToken(User user);
}
