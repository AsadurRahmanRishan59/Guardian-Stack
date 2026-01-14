package com.rishan.guardianstack.auth.service.impl;

import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.auth.service.ELKAuditService;
import com.rishan.guardianstack.auth.service.MailService;
import com.rishan.guardianstack.core.logging.AuditEventType;
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

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Service
@RequiredArgsConstructor
public class MailServiceImpl implements MailService {
    private final JavaMailSender mailSender;
    private final ELKAuditService elkAuditService;
    private static final Logger log = LoggerFactory.getLogger(MailServiceImpl.class);
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("MMM dd, yyyy 'at' hh:mm a");

    @Async("emailExecutor")
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

            elkAuditService.logSuccess(
                    AuditEventType.EMAIL_VERIFICATION_SENT,
                    null,
                    "Verification email sent to: " + to
            );
        } catch (MessagingException e) {
            log.error("Failed to send verification email to {}: {}", to, e.getMessage());

            elkAuditService.logFailure(
                    AuditEventType.EMAIL_SEND_FAILED,
                    to,
                    "Verification email failed: " + e.getMessage()
            );
            throw new IllegalStateException("Failed to send email", e);
        }
    }

    @Async("emailExecutor")
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
            message.setFrom("no-reply@guardianstack.com");

            mailSender.send(message);

            elkAuditService.logSuccess(
                    AuditEventType.EMAIL_PASSWORD_RESET_SENT,
                    null,
                    "Password reset email sent to: " + to + " (username: " + username + ")"
            );
        } catch (Exception e) {
            log.error("Failed to send password reset email to {}: {}", to, e.getMessage());

            elkAuditService.logFailure(
                    AuditEventType.EMAIL_SEND_FAILED,
                    to,
                    "Password reset email failed: " + e.getMessage()
            );
        }
    }

    @Async("emailExecutor")
    @Override
    public void sendEmployeeWelcomeEmail(String to, String username, String tempPassword,
                                         LocalDateTime accountExpiry, LocalDateTime passwordExpiry) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            String htmlContent = "<h3>Welcome to GuardianStack, " + username + "!</h3>" +
                    "<p>Your employee account has been created by an administrator.</p>" +
                    "<div style='background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;'>" +
                    "<p><strong>Temporary Password:</strong> <code style='background-color: #fff; padding: 5px;'>" + tempPassword + "</code></p>" +
                    "<p><strong>Password Expires:</strong> " + passwordExpiry.format(DATE_FORMATTER) + "</p>" +
                    "<p><strong>Contract Ends:</strong> " + accountExpiry.format(DATE_FORMATTER) + "</p>" +
                    "</div>" +
                    "<p><strong>⚠️ Important:</strong></p>" +
                    "<ul>" +
                    "<li>You must change this temporary password on your first login</li>" +
                    "<li>Keep your password secure and do not share it</li>" +
                    "<li>Your account will expire at the contract end date</li>" +
                    "</ul>" +
                    "<p>If you have any questions, please contact your administrator.</p>" +
                    "<p>Best regards,<br>The GuardianStack Team</p>";

            helper.setText(htmlContent, true);
            helper.setTo(to);
            helper.setSubject("GuardianStack - Your Employee Account");
            helper.setFrom("no-reply@guardianstack.com");

            mailSender.send(mimeMessage);
            log.info("✓ Sent welcome email to: {}", to);

            elkAuditService.logSuccess(
                    AuditEventType.EMAIL_EMPLOYEE_WELCOME_SENT,
                    null,
                    String.format("Employee welcome email sent to: %s (expires: %s)",
                            to, accountExpiry.format(DATE_FORMATTER))
            );
        } catch (MessagingException e) {
            log.error("Failed to send employee welcome email to {}: {}", to, e.getMessage());

            elkAuditService.logFailure(
                    AuditEventType.EMAIL_SEND_FAILED,
                    to,
                    "Employee welcome email failed: " + e.getMessage()
            );
        }
    }

    @Async("emailExecutor")
    @Override
    public void sendContractExtendedEmail(String to, String username, int additionalDays,
                                          LocalDateTime newExpiryDate) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject("GuardianStack - Contract Extended");
            message.setText("Hello " + username + ",\n\n" +
                    "Good news! Your contract has been extended.\n\n" +
                    "Extension: " + additionalDays + " days\n" +
                    "New Contract End Date: " + newExpiryDate.format(DATE_FORMATTER) + "\n\n" +
                    "Your account will remain active until the new expiry date.\n\n" +
                    "Best regards,\n" +
                    "The GuardianStack Team");
            message.setFrom("no-reply@guardianstack.com");

            mailSender.send(message);
            log.info("✓ Sent contract extension email to: {}", to);

            elkAuditService.logSuccess(
                    AuditEventType.EMAIL_CONTRACT_EXTENDED_SENT,
                    null,
                    String.format("Contract extension email sent to: %s (+%d days, new expiry: %s)",
                            to, additionalDays, newExpiryDate.format(DATE_FORMATTER))
            );
        } catch (Exception e) {
            log.error("Failed to send contract extension email to {}: {}", to, e.getMessage());

            elkAuditService.logFailure(
                    AuditEventType.EMAIL_SEND_FAILED,
                    to,
                    "Contract extension email failed: " + e.getMessage()
            );
        }
    }

    @Async("emailExecutor")
    @Override
    public void sendPasswordChangeRequired(String to, String username, int daysToChange) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            String htmlContent = "<h3>Password Change Required</h3>" +
                    "<p>Hello " + username + ",</p>" +
                    "<p>An administrator has required you to change your password.</p>" +
                    "<div style='background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0;'>" +
                    "<p><strong>⚠️ Action Required:</strong></p>" +
                    "<p>You have <strong>" + daysToChange + " days</strong> to change your password.</p>" +
                    "<p>After this period, your account access may be restricted.</p>" +
                    "</div>" +
                    "<p>Please log in and update your password as soon as possible.</p>" +
                    "<p>Best regards,<br>The GuardianStack Team</p>";

            helper.setText(htmlContent, true);
            helper.setTo(to);
            helper.setSubject("GuardianStack - Password Change Required");
            helper.setFrom("no-reply@guardianstack.com");

            mailSender.send(mimeMessage);
            log.info("✓ Sent password change required email to: {}", to);

            elkAuditService.logSuccess(
                    AuditEventType.EMAIL_PASSWORD_CHANGE_REQUIRED_SENT,
                    null,
                    String.format("Password change required email sent to: %s (deadline: %d days)",
                            to, daysToChange)
            );
        } catch (MessagingException e) {
            log.error("Failed to send password change required email to {}: {}", to, e.getMessage());

            elkAuditService.logFailure(
                    AuditEventType.EMAIL_SEND_FAILED,
                    to,
                    "Password change required email failed: " + e.getMessage()
            );
        }
    }

    @Async("emailExecutor")
    @Override
    public void sendPasswordResetByAdmin(String to, String username, String tempPassword,
                                         int expiryDays) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            String htmlContent = "<h3>Password Reset by Administrator</h3>" +
                    "<p>Hello " + username + ",</p>" +
                    "<p>Your password has been reset by an administrator.</p>" +
                    "<div style='background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;'>" +
                    "<p><strong>New Temporary Password:</strong> <code style='background-color: #fff; padding: 5px;'>" + tempPassword + "</code></p>" +
                    "<p><strong>Valid for:</strong> " + expiryDays + " days</p>" +
                    "</div>" +
                    "<p><strong>⚠️ Important:</strong></p>" +
                    "<ul>" +
                    "<li>You must change this password on your next login</li>" +
                    "<li>This temporary password will expire in " + expiryDays + " days</li>" +
                    "<li>Keep your new password secure</li>" +
                    "</ul>" +
                    "<p>If you did not request this reset, please contact your administrator immediately.</p>" +
                    "<p>Best regards,<br>The GuardianStack Team</p>";

            helper.setText(htmlContent, true);
            helper.setTo(to);
            helper.setSubject("GuardianStack - Password Reset by Admin");
            helper.setFrom("no-reply@guardianstack.com");

            mailSender.send(mimeMessage);
            log.info("✓ Sent admin password reset email to: {}", to);

            elkAuditService.logSuccess(
                    AuditEventType.EMAIL_PASSWORD_RESET_BY_ADMIN_SENT,
                    null,
                    String.format("Admin password reset email sent to: %s (expires in %d days)",
                            to, expiryDays)
            );
        } catch (MessagingException e) {
            log.error("Failed to send admin password reset email to {}: {}", to, e.getMessage());

            elkAuditService.logFailure(
                    AuditEventType.EMAIL_SEND_FAILED,
                    to,
                    "Admin password reset email failed: " + e.getMessage()
            );
        }
    }

    @Async("emailExecutor")
    @Override
    public void sendAccountDeactivatedEmail(String to, String username, String reason) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject("GuardianStack - Account Deactivated");
            message.setText("Hello " + username + ",\n\n" +
                    "Your GuardianStack account has been deactivated.\n\n" +
                    "Reason: " + reason + "\n\n" +
                    "You will no longer be able to access your account. If you believe this is an error, " +
                    "please contact your administrator.\n\n" +
                    "Best regards,\n" +
                    "The GuardianStack Team");
            message.setFrom("no-reply@guardianstack.com");

            mailSender.send(message);
            log.info("✓ Sent account deactivation email to: {}", to);

            elkAuditService.logSuccess(
                    AuditEventType.EMAIL_ACCOUNT_DEACTIVATED_SENT,
                    null,
                    String.format("Account deactivation email sent to: %s (reason: %s)",
                            to, reason)
            );
        } catch (Exception e) {
            log.error("Failed to send account deactivation email to {}: {}", to, e.getMessage());

            elkAuditService.logFailure(
                    AuditEventType.EMAIL_SEND_FAILED,
                    to,
                    "Account deactivation email failed: " + e.getMessage()
            );
        }
    }

    @Async("emailExecutor")
    @Override
    public void sendAccountReactivatedEmail(String to, String username, int contractDays,
                                            LocalDateTime newExpiryDate) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            String htmlContent = "<h3>Account Reactivated</h3>" +
                    "<p>Hello " + username + ",</p>" +
                    "<p>Great news! Your GuardianStack account has been reactivated.</p>" +
                    "<div style='background-color: #d1ecf1; padding: 15px; border-left: 4px solid #0c5460; margin: 20px 0;'>" +
                    "<p><strong>✓ Account Status:</strong> Active</p>" +
                    "<p><strong>Contract Duration:</strong> " + contractDays + " days</p>" +
                    "<p><strong>Contract End Date:</strong> " + newExpiryDate.format(DATE_FORMATTER) + "</p>" +
                    "</div>" +
                    "<p>You can now log in and access your account.</p>" +
                    "<p>Best regards,<br>The GuardianStack Team</p>";

            helper.setText(htmlContent, true);
            helper.setTo(to);
            helper.setSubject("GuardianStack - Account Reactivated");
            helper.setFrom("no-reply@guardianstack.com");

            mailSender.send(mimeMessage);
            log.info("✓ Sent account reactivation email to: {}", to);

            elkAuditService.logSuccess(
                    AuditEventType.EMAIL_ACCOUNT_REACTIVATED_SENT,
                    null,
                    String.format("Account reactivation email sent to: %s (contract: %d days, expires: %s)",
                            to, contractDays, newExpiryDate.format(DATE_FORMATTER))
            );
        } catch (MessagingException e) {
            log.error("Failed to send account reactivation email to {}: {}", to, e.getMessage());

            elkAuditService.logFailure(
                    AuditEventType.EMAIL_SEND_FAILED,
                    to,
                    "Account reactivation email failed: " + e.getMessage()
            );
        }
    }

    @Async("emailExecutor")
    @Override
    public void sendAccountExpiryWarning(String to, String username, long daysLeft) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            String urgencyLevel = daysLeft <= 3 ? "⚠️ URGENT" : "⚠️ Notice";
            String urgencyColor = daysLeft <= 3 ? "#dc3545" : "#ffc107";

            String htmlContent = "<h3>" + urgencyLevel + ": Account Expiring Soon</h3>" +
                    "<p>Hello " + username + ",</p>" +
                    "<p>This is a reminder that your account is expiring soon.</p>" +
                    "<div style='background-color: #fff3cd; padding: 15px; border-left: 4px solid " + urgencyColor + "; margin: 20px 0;'>" +
                    "<p><strong>Days Remaining:</strong> " + daysLeft + " day" + (daysLeft != 1 ? "s" : "") + "</p>" +
                    "</div>" +
                    "<p>Please contact your administrator if you need to extend your account access.</p>" +
                    "<p>After the expiry date, your account will be automatically disabled and you will no longer be able to log in.</p>" +
                    "<p>Best regards,<br>The GuardianStack Team</p>";

            helper.setText(htmlContent, true);
            helper.setTo(to);
            helper.setSubject("GuardianStack - Account Expiring in " + daysLeft + " Day" + (daysLeft != 1 ? "s" : ""));
            helper.setFrom("no-reply@guardianstack.com");

            mailSender.send(mimeMessage);
            log.info("✓ Sent account expiry warning to: {} ({} days left)", to, daysLeft);

            elkAuditService.logSuccess(
                    AuditEventType.EMAIL_ACCOUNT_EXPIRY_WARNING_SENT,
                    null,
                    String.format("Account expiry warning sent to: %s (days left: %d)", to, daysLeft)
            );
        } catch (MessagingException e) {
            log.error("Failed to send account expiry warning to {}: {}", to, e.getMessage());

            elkAuditService.logFailure(
                    AuditEventType.EMAIL_SEND_FAILED,
                    to,
                    "Account expiry warning email failed: " + e.getMessage()
            );
        }
    }

    @Async("emailExecutor")
    @Override
    public void sendContractExpiryWarning(String to, String username, long daysLeft,
                                          LocalDateTime expiryDate) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            String urgencyLevel = daysLeft <= 3 ? "⚠️ URGENT" : "⚠️ Notice";
            String urgencyColor = daysLeft <= 3 ? "#dc3545" : "#ffc107";

            String htmlContent = "<h3>" + urgencyLevel + ": Contract Expiring Soon</h3>" +
                    "<p>Hello " + username + ",</p>" +
                    "<p>This is a reminder that your contract is expiring soon.</p>" +
                    "<div style='background-color: #fff3cd; padding: 15px; border-left: 4px solid " + urgencyColor + "; margin: 20px 0;'>" +
                    "<p><strong>Days Remaining:</strong> " + daysLeft + " day" + (daysLeft != 1 ? "s" : "") + "</p>" +
                    "<p><strong>Contract End Date:</strong> " + expiryDate.format(DATE_FORMATTER) + "</p>" +
                    "</div>" +
                    "<p>Please contact your administrator if you need to extend your contract.</p>" +
                    "<p>After the expiry date, your account will be automatically disabled.</p>" +
                    "<p>Best regards,<br>The GuardianStack Team</p>";

            helper.setText(htmlContent, true);
            helper.setTo(to);
            helper.setSubject("GuardianStack - Contract Expiring in " + daysLeft + " Day" + (daysLeft != 1 ? "s" : ""));
            helper.setFrom("no-reply@guardianstack.com");

            mailSender.send(mimeMessage);
            log.info("✓ Sent contract expiry warning to: {} ({} days left)", to, daysLeft);

            elkAuditService.logSuccess(
                    AuditEventType.EMAIL_CONTRACT_EXPIRY_WARNING_SENT,
                    null,
                    String.format("Contract expiry warning sent to: %s (days left: %d, expires: %s)",
                            to, daysLeft, expiryDate.format(DATE_FORMATTER))
            );
        } catch (MessagingException e) {
            log.error("Failed to send contract expiry warning to {}: {}", to, e.getMessage());

            elkAuditService.logFailure(
                    AuditEventType.EMAIL_SEND_FAILED,
                    to,
                    "Contract expiry warning email failed: " + e.getMessage()
            );
        }
    }

    @Async("emailExecutor")
    @Override
    public void sendPasswordExpiryWarning(String to, String username, long daysLeft) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            String htmlContent = "<h3>⚠️ Password Expiring Soon</h3>" +
                    "<p>Hello " + username + ",</p>" +
                    "<p>Your password is expiring soon and must be changed.</p>" +
                    "<div style='background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0;'>" +
                    "<p><strong>Days Remaining:</strong> " + daysLeft + " day" + (daysLeft != 1 ? "s" : "") + "</p>" +
                    "</div>" +
                    "<p><strong>Action Required:</strong> Please log in and change your password before it expires.</p>" +
                    "<p>After expiration, you will be required to change your password on your next login.</p>" +
                    "<p>Best regards,<br>The GuardianStack Team</p>";

            helper.setText(htmlContent, true);
            helper.setTo(to);
            helper.setSubject("GuardianStack - Password Expiring in " + daysLeft + " Day" + (daysLeft != 1 ? "s" : ""));
            helper.setFrom("no-reply@guardianstack.com");

            mailSender.send(mimeMessage);
            log.info("✓ Sent password expiry warning to: {} ({} days left)", to, daysLeft);

            elkAuditService.logSuccess(
                    AuditEventType.EMAIL_PASSWORD_EXPIRY_WARNING_SENT,
                    null,
                    String.format("Password expiry warning sent to: %s (days left: %d)", to, daysLeft)
            );
        } catch (MessagingException e) {
            log.error("Failed to send password expiry warning to {}: {}", to, e.getMessage());

            elkAuditService.logFailure(
                    AuditEventType.EMAIL_SEND_FAILED,
                    to,
                    "Password expiry warning email failed: " + e.getMessage()
            );
        }
    }

    @Async("emailExecutor")
    @Override
    public void sendAccountExpiredNotification(String to, String username,
                                               LocalDateTime expiryDate) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject("GuardianStack - Account Expired");
            message.setText("Hello " + username + ",\n\n" +
                    "Your GuardianStack account has expired and has been automatically disabled.\n\n" +
                    "Contract End Date: " + expiryDate.format(DATE_FORMATTER) + "\n\n" +
                    "If you need to regain access, please contact your administrator about extending your contract.\n\n" +
                    "Best regards,\n" +
                    "The GuardianStack Team");
            message.setFrom("no-reply@guardianstack.com");

            mailSender.send(message);
            log.info("✓ Sent account expired notification to: {}", to);

            elkAuditService.logSuccess(
                    AuditEventType.EMAIL_ACCOUNT_EXPIRED_SENT,
                    null,
                    String.format("Account expired notification sent to: %s (expired: %s)",
                            to, expiryDate.format(DATE_FORMATTER))
            );
        } catch (Exception e) {
            log.error("Failed to send account expired notification to {}: {}", to, e.getMessage());

            elkAuditService.logFailure(
                    AuditEventType.EMAIL_SEND_FAILED,
                    to,
                    "Account expired notification email failed: " + e.getMessage()
            );
        }
    }

    @Async("emailExecutor")
    @Override
    public void sendPasswordExpiredNotification(String to, String username) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            String htmlContent = "<h3>🔒 Password Expired</h3>" +
                    "<p>Hello " + username + ",</p>" +
                    "<p>Your password has expired.</p>" +
                    "<div style='background-color: #f8d7da; padding: 15px; border-left: 4px solid #dc3545; margin: 20px 0;'>" +
                    "<p><strong>⚠️ Action Required:</strong></p>" +
                    "<p>You must change your password on your next login to continue using your account.</p>" +
                    "</div>" +
                    "<p>For security reasons, you will be prompted to create a new password when you log in.</p>" +
                    "<p>Best regards,<br>The GuardianStack Team</p>";

            helper.setText(htmlContent, true);
            helper.setTo(to);
            helper.setSubject("GuardianStack - Password Expired");
            helper.setFrom("no-reply@guardianstack.com");

            mailSender.send(mimeMessage);
            log.info("✓ Sent password expired notification to: {}", to);

            elkAuditService.logSuccess(
                    AuditEventType.EMAIL_PASSWORD_EXPIRED_SENT,
                    null,
                    String.format("Password expired notification sent to: %s", to)
            );
        } catch (MessagingException e) {
            log.error("Failed to send password expired notification to {}: {}", to, e.getMessage());

            elkAuditService.logFailure(
                    AuditEventType.EMAIL_SEND_FAILED,
                    to,
                    "Password expired notification email failed: " + e.getMessage()
            );
        }
    }

    @Async("emailExecutor")
    @Override
    public void sendWeeklyExpirationReportToAdmins(List<User> expiringSoon,
                                                   List<User> passwordsExpiringSoon,
                                                   List<User> expiredStillEnabled) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");

            StringBuilder htmlContent = new StringBuilder();
            htmlContent.append("<h2>📊 Weekly Employee Expiration Report</h2>");
            htmlContent.append("<p>This is your weekly summary of employee contract and password expirations.</p>");

            // Contracts expiring section
            htmlContent.append("<div style='margin: 20px 0;'>");
            htmlContent.append("<h3 style='color: #0c5460;'>Contracts Expiring in Next 30 Days (" + expiringSoon.size() + ")</h3>");
            if (expiringSoon.isEmpty()) {
                htmlContent.append("<p>No contracts expiring soon.</p>");
            } else {
                htmlContent.append("<table style='border-collapse: collapse; width: 100%;'>");
                htmlContent.append("<tr style='background-color: #f8f9fa;'>");
                htmlContent.append("<th style='border: 1px solid #dee2e6; padding: 8px; text-align: left;'>Employee</th>");
                htmlContent.append("<th style='border: 1px solid #dee2e6; padding: 8px; text-align: left;'>Email</th>");
                htmlContent.append("<th style='border: 1px solid #dee2e6; padding: 8px; text-align: left;'>Days Left</th>");
                htmlContent.append("<th style='border: 1px solid #dee2e6; padding: 8px; text-align: left;'>Expiry Date</th>");
                htmlContent.append("</tr>");

                for (User user : expiringSoon) {
                    long daysLeft = user.getDaysUntilAccountExpiry();
                    String rowColor = daysLeft <= 7 ? "#fff3cd" : "#ffffff";
                    htmlContent.append("<tr style='background-color: " + rowColor + ";'>");
                    htmlContent.append("<td style='border: 1px solid #dee2e6; padding: 8px;'>" + user.getUsername() + "</td>");
                    htmlContent.append("<td style='border: 1px solid #dee2e6; padding: 8px;'>" + user.getEmail() + "</td>");
                    htmlContent.append("<td style='border: 1px solid #dee2e6; padding: 8px;'>" + daysLeft + "</td>");
                    htmlContent.append("<td style='border: 1px solid #dee2e6; padding: 8px;'>" +
                            user.getAccountExpiryDate().format(DATE_FORMATTER) + "</td>");
                    htmlContent.append("</tr>");
                }
                htmlContent.append("</table>");
            }
            htmlContent.append("</div>");

            // Passwords expiring section
            htmlContent.append("<div style='margin: 20px 0;'>");
            htmlContent.append("<h3 style='color: #0c5460;'>Passwords Expiring in Next 30 Days (" + passwordsExpiringSoon.size() + ")</h3>");
            if (passwordsExpiringSoon.isEmpty()) {
                htmlContent.append("<p>No passwords expiring soon.</p>");
            } else {
                htmlContent.append("<table style='border-collapse: collapse; width: 100%;'>");
                htmlContent.append("<tr style='background-color: #f8f9fa;'>");
                htmlContent.append("<th style='border: 1px solid #dee2e6; padding: 8px; text-align: left;'>Employee</th>");
                htmlContent.append("<th style='border: 1px solid #dee2e6; padding: 8px; text-align: left;'>Email</th>");
                htmlContent.append("<th style='border: 1px solid #dee2e6; padding: 8px; text-align: left;'>Days Left</th>");
                htmlContent.append("</tr>");

                for (User user : passwordsExpiringSoon) {
                    long daysLeft = user.getDaysUntilPasswordExpiry();
                    String rowColor = daysLeft <= 7 ? "#fff3cd" : "#ffffff";
                    htmlContent.append("<tr style='background-color: " + rowColor + ";'>");
                    htmlContent.append("<td style='border: 1px solid #dee2e6; padding: 8px;'>" + user.getUsername() + "</td>");
                    htmlContent.append("<td style='border: 1px solid #dee2e6; padding: 8px;'>" + user.getEmail() + "</td>");
                    htmlContent.append("<td style='border: 1px solid #dee2e6; padding: 8px;'>" + daysLeft + "</td>");
                    htmlContent.append("</tr>");
                }
                htmlContent.append("</table>");
            }
            htmlContent.append("</div>");

            // Anomalies section
            if (!expiredStillEnabled.isEmpty()) {
                htmlContent.append("<div style='margin: 20px 0; background-color: #f8d7da; padding: 15px; border-left: 4px solid #dc3545;'>");
                htmlContent.append("<h3 style='color: #721c24;'>⚠️ Anomalies Detected (" + expiredStillEnabled.size() + ")</h3>");
                htmlContent.append("<p>The following accounts are expired but still enabled. This requires immediate attention:</p>");
                htmlContent.append("<ul>");
                for (User user : expiredStillEnabled) {
                    htmlContent.append("<li><strong>" + user.getEmail() + "</strong> - Expired: " +
                            user.getAccountExpiryDate().format(DATE_FORMATTER) + "</li>");
                }
                htmlContent.append("</ul>");
                htmlContent.append("</div>");
            }

            htmlContent.append("<p style='margin-top: 30px;'>This is an automated weekly report.</p>");
            htmlContent.append("<p>Best regards,<br>GuardianStack System</p>");

            helper.setText(htmlContent.toString(), true);
            helper.setTo("admin@guardianstack.com"); // Configure admin email in properties
            helper.setSubject("GuardianStack - Weekly Employee Expiration Report");
            helper.setFrom("no-reply@guardianstack.com");

            mailSender.send(mimeMessage);
            log.info("✓ Sent weekly expiration report to admins");

            elkAuditService.logSuccess(
                    AuditEventType.EMAIL_WEEKLY_REPORT_SENT,
                    null,
                    String.format("Weekly report sent: %d contracts expiring, %d passwords expiring, %d anomalies",
                            expiringSoon.size(), passwordsExpiringSoon.size(), expiredStillEnabled.size())
            );
        } catch (MessagingException e) {
            log.error("Failed to send weekly expiration report: {}", e.getMessage());

            elkAuditService.logFailure(
                    AuditEventType.EMAIL_SEND_FAILED,
                    "admin@guardianstack.com",
                    "Weekly expiration report failed: " + e.getMessage()
            );
        }
    }
}