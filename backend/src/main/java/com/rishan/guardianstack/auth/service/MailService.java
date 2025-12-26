package com.rishan.guardianstack.auth.service;

public interface MailService {
    void sendVerificationEmail(String to, String name, String otp);
    void sendPasswordResetEmail(String to, String username, String otp);
}
