package com.rishan.guardianstack.auth.service.impl;

import com.rishan.guardianstack.auth.service.MailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MailServiceImpl implements MailService {
    private final JavaMailSender mailSender;
    private static final Logger log = LoggerFactory.getLogger(MailServiceImpl.class);

    @Async // Runs in the background so the user doesn't wait for the email to send
    public void sendVerificationEmail(String to, String name, String otp) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            String htmlContent = "<h3>Welcome to GuardianStack, " + name + "!</h3>" +
                    "<p>Your verification code is: <b>" + otp + "</b></p>" +
                    "<p>This code will expire in 15 minutes.</p>";

            helper.setText(htmlContent, true);
            helper.setTo(to);
            helper.setSubject("Verify Your GuardianStack Account");
            helper.setFrom("no-reply@guardianstack.com");

            mailSender.send(mimeMessage);
        } catch (MessagingException e) {
            throw new IllegalStateException("Failed to send email", e);
        }
    }

    @Async
    @Override
    public void sendPasswordResetEmail(String to, String username, String otp) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject("GuardianStack - Password Reset Request");
            message.setText("Hello " + username + ",\n\n" +
                    "You requested to reset your password. Use the following 6-digit code to proceed:\n\n" +
                    "OTP: " + otp + "\n\n" +
                    "This code will expire in 10 minutes. If you did not request this, please ignore this email.\n\n" +
                    "Stay secure,\n" +
                    "The GuardianStack Team");

            mailSender.send(message);
        } catch (Exception e) {
            // Since it's @Async, we log the error so the main thread doesn't crash
            log.error("Failed to send password reset email to {}: {}", to, e.getMessage());
        }
    }
}