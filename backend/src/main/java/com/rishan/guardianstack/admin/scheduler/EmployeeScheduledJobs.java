package com.rishan.guardianstack.admin.scheduler;

import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.auth.repository.UserRepository;
import com.rishan.guardianstack.auth.service.AuditService;
import com.rishan.guardianstack.auth.service.MailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class EmployeeScheduledJobs {

    private final UserRepository userRepository;
    private final MailService mailService;
    private final AuditService auditService;

    /**
     * Notify employees of expiring contracts (7 days warning)
     * Runs daily at 9:00 AM
     */
    @Scheduled(cron = "${app.security.employee.contract-warning-cron:0 0 9 * * ?}")
    @Transactional
    public void notifyExpiringContracts() {
        log.info("🔍 Checking for expiring employee contracts...");

        List<User> expiringEmployees = userRepository.findUsersWithExpiringAccounts(7)
                .stream()
                .filter(User::isEmployee)
                .toList();

        for (User employee : expiringEmployees) {
            long daysLeft = employee.getDaysUntilAccountExpiry();

            mailService.sendContractExpiryWarning(
                    employee.getEmail(),
                    employee.getUsername(),
                    daysLeft,
                    employee.getAccountExpiryDate()
            );

            auditService.logEvent(
                    "CONTRACT_EXPIRY_WARNING",
                    employee,
                    true,
                    "system",
                    "system",
                    String.format("Contract expiry warning sent (%d days left)", daysLeft)
            );

            log.info("⚠️ Sent contract expiry warning to: {} ({} days left)",
                    employee.getEmail(), daysLeft);
        }

        log.info("✓ Processed {} expiring contracts", expiringEmployees.size());
    }

    /**
     * Notify employees of expiring passwords (14 days warning)
     * Runs daily at 9:00 AM
     */
    @Scheduled(cron = "${app.security.employee.password-warning-cron:0 0 9 * * ?}")
    @Transactional
    public void notifyExpiringPasswords() {
        log.info("🔍 Checking for expiring passwords...");

        List<User> usersWithExpiringPasswords = userRepository
                .findUsersWithExpiringCredentials(14)
                .stream()
                .filter(User::isEmployee)
                .toList();

        for (User employee : usersWithExpiringPasswords) {
            long daysLeft = employee.getDaysUntilPasswordExpiry();

            mailService.sendPasswordExpiryWarning(
                    employee.getEmail(),
                    employee.getUsername(),
                    daysLeft
            );

            auditService.logEvent(
                    "PASSWORD_EXPIRY_WARNING",
                    employee,
                    true,
                    "system",
                    "system",
                    String.format("Password expiry warning sent (%d days left)", daysLeft)
            );

            log.info("⚠️ Sent password expiry warning to: {} ({} days left)",
                    employee.getEmail(), daysLeft);
        }

        log.info("✓ Processed {} expiring passwords", usersWithExpiringPasswords.size());
    }

    /**
     * Disable expired employee accounts
     * Runs daily at 2:00 AM
     */
    @Scheduled(cron = "${app.security.employee.expiry-check-cron:0 0 2 * * ?}")
    @Transactional
    public void disableExpiredAccounts() {
        log.info("🔍 Checking for expired employee accounts...");

        List<User> expiredEmployees = userRepository.findExpiredAccounts()
                .stream()
                .filter(User::isEmployee)
                .filter(User::isEnabled)
                .toList();

        for (User employee : expiredEmployees) {
            employee.setEnabled(false);
            userRepository.save(employee);

            mailService.sendAccountExpiredNotification(
                    employee.getEmail(),
                    employee.getUsername(),
                    employee.getAccountExpiryDate()
            );

            auditService.logEvent(
                    "ACCOUNT_EXPIRED_AUTO_DISABLED",
                    employee,
                    false,
                    "system",
                    "system",
                    "Account automatically disabled due to contract expiration"
            );

            log.warn("🚫 Disabled expired employee account: {} (expired: {})",
                    employee.getEmail(), employee.getAccountExpiryDate());
        }

        log.info("✓ Disabled {} expired accounts", expiredEmployees.size());
    }

    /**
     * Force password reset for users with expired credentials
     * Runs daily at 2:00 AM
     */
    @Scheduled(cron = "${app.security.employee.expiry-check-cron:0 0 2 * * ?}")
    @Transactional
    public void handleExpiredPasswords() {
        log.info("🔍 Checking for expired passwords...");

        List<User> usersWithExpiredPasswords = userRepository
                .findUsersWithExpiredCredentials()
                .stream()
                .filter(User::isEmployee)
                .filter(User::isEnabled)
                .toList();

        for (User employee : usersWithExpiredPasswords) {
            // Mark that password must be changed
            employee.setMustChangePassword(true);
            userRepository.save(employee);

            mailService.sendPasswordExpiredNotification(
                    employee.getEmail(),
                    employee.getUsername()
            );

            auditService.logEvent(
                    "PASSWORD_EXPIRED",
                    employee,
                    false,
                    "system",
                    "system",
                    "Password expired - must change on next login"
            );

            log.warn("🔒 Password expired for: {} (must change on next login)",
                    employee.getEmail());
        }

        log.info("✓ Processed {} expired passwords", usersWithExpiredPasswords.size());
    }

    /**
     * Send weekly report to admins about upcoming expirations
     * Runs every Monday at 8:00 AM
     */
    @Scheduled(cron = "${app.security.employee.weekly-report-cron:0 0 8 * * MON}")
    @Transactional(readOnly = true)
    public void sendWeeklyExpirationReport() {
        log.info("📊 Generating weekly expiration report...");

        // Contracts expiring in next 30 days
        List<User> expiringSoon = userRepository.findUsersWithExpiringAccounts(30)
                .stream()
                .filter(User::isEmployee)
                .toList();

        // Passwords expiring in next 30 days
        List<User> passwordsExpiringSoon = userRepository.findUsersWithExpiringCredentials(30)
                .stream()
                .filter(User::isEmployee)
                .toList();

        // Expired but still enabled (should not happen)
        List<User> expiredStillEnabled = userRepository.findExpiredAccounts()
                .stream()
                .filter(User::isEmployee)
                .filter(User::isEnabled)
                .toList();

        // Send report to admins
        mailService.sendWeeklyExpirationReportToAdmins(
                expiringSoon,
                passwordsExpiringSoon,
                expiredStillEnabled
        );

        log.info("✓ Weekly report sent: {} contracts expiring, {} passwords expiring, {} anomalies",
                expiringSoon.size(),
                passwordsExpiringSoon.size(),
                expiredStillEnabled.size());
    }
}