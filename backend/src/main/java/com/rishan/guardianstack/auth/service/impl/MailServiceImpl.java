package com.rishan.guardianstack.auth.service.impl;

import com.rishan.guardianstack.auth.service.MailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MailServiceImpl implements MailService {
    private final JavaMailSender mailSender;

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
}