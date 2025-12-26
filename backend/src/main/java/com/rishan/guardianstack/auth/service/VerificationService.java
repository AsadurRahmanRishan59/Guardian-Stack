package com.rishan.guardianstack.auth.service;

import com.rishan.guardianstack.auth.model.User;

public interface VerificationService {
    String createToken(User user);
    User verifyToken(String email, String otp);
    String createPasswordResetToken(User user);
}
