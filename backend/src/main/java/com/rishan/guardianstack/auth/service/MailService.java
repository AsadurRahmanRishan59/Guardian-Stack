package com.rishan.guardianstack.auth.service;

import com.rishan.guardianstack.auth.model.User;

import java.time.LocalDateTime;
import java.util.List;

public interface MailService {
    void sendVerificationEmail(String to, String name, String otp);

    void sendPasswordResetEmail(String to, String username, String otp);

    void sendEmployeeWelcomeEmail(String to, String username, String tempPassword,
                                  LocalDateTime accountExpiry, LocalDateTime passwordExpiry);

    void sendContractExtendedEmail(String to, String username, int additionalDays,
                                   LocalDateTime newExpiryDate);

    void sendPasswordChangeRequired(String to, String username, int daysToChange);

    void sendPasswordResetByAdmin(String to, String username, String tempPassword,
                                  int expiryDays);

    void sendAccountDeactivatedEmail(String to, String username, String reason);

    void sendAccountReactivatedEmail(String to, String username, int contractDays,
                                     LocalDateTime newExpiryDate);

    void sendAccountExpiryWarning(String to, String username, long daysLeft);

    void sendContractExpiryWarning(String to, String username, long daysLeft,
                                   LocalDateTime expiryDate);

    void sendPasswordExpiryWarning(String to, String username, long daysLeft);

    void sendAccountExpiredNotification(String to, String username,
                                        LocalDateTime expiryDate);

    void sendPasswordExpiredNotification(String to, String username);

    void sendWeeklyExpirationReportToAdmins(List<User> expiringSoon,
                                            List<User> passwordsExpiringSoon,
                                            List<User> expiredStillEnabled);
}