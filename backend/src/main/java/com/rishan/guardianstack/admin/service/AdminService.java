package com.rishan.guardianstack.admin.service;

import com.rishan.guardianstack.admin.dto.CreateEmployeeRequest;
import com.rishan.guardianstack.admin.dto.ExtendAccountRequest;
import com.rishan.guardianstack.auth.model.*;
import com.rishan.guardianstack.auth.repository.RoleRepository;
import com.rishan.guardianstack.auth.repository.UserRepository;
import com.rishan.guardianstack.auth.service.AuditService;
import com.rishan.guardianstack.auth.service.MailService;
import com.rishan.guardianstack.core.exception.MultipleFieldValidationException;
import com.rishan.guardianstack.core.exception.ResourceNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final MailService mailService;
    private final AuditService auditService;

    @Value("${app.security.employee.default-contract-days}")
    private int defaultContractDays;

    @Value("${app.security.employee.temp-password-expiry-days}")
    private int tempPasswordExpiryDays;

    @Value("${app.security.employee.password-rotation-days:90}")
    private int passwordRotationDays;

    /**
     * Admin creates employee account with temporary password
     */
    @Transactional
    public User createEmployeeAccount(CreateEmployeeRequest request, HttpServletRequest httpRequest) {
        // Validation
        Map<String, String> errors = new HashMap<>();

        if (userRepository.existsByEmail(request.email())) {
            errors.put("email", "Email already exists");
        }

        if (request.contractDays() != null && request.contractDays() < 1) {
            errors.put("contractDays", "Contract days must be positive");
        }

        if (!errors.isEmpty()) {
            throw new MultipleFieldValidationException(errors);
        }

        // Get role
        Role role = roleRepository.findByRoleName(request.role())
                .orElseThrow(() -> new ResourceNotFoundException("Role not found"));

        // Generate temporary password
        String tempPassword = generateTemporaryPassword();
        String encodedPassword = passwordEncoder.encode(tempPassword);

        // Calculate expiry dates
        int contractDays = request.contractDays() != null ? request.contractDays() : defaultContractDays;

        // Build user
        User employee = User.builder()
                .username(request.username())
                .email(request.email())
                .password(encodedPassword)
                .roles(Collections.singleton(role))
                .enabled(true) // Employee accounts are immediately active
                .signUpMethod(SignUpMethod.ADMIN_CREATED)
                .failedLoginAttempts(0)
                .accountLocked(false)
                .mustChangePassword(true) // Force password change on first login
                .build();

        // Set account expiry (contract end date)
        employee.setAccountExpiry(contractDays);

        // Set temporary password expiry
        employee.setPasswordExpiry(tempPasswordExpiryDays);

        // Save
        User savedEmployee = userRepository.save(employee);

        // Send welcome email with temporary password
        mailService.sendEmployeeWelcomeEmail(
                employee.getEmail(),
                employee.getUsername(),
                tempPassword,
                employee.getAccountExpiryDate(),
                employee.getCredentialsExpiryDate()
        );

        // Audit log
        auditService.logEvent(
                "EMPLOYEE_CREATED",
                savedEmployee,
                true,
                auditService.getClientIp(httpRequest),
                auditService.getUserAgent(httpRequest),
                String.format("Employee created with role: %s, contract: %d days",
                        role.getRoleName(), contractDays)
        );

        log.info("✓ Created employee account: {} (Role: {}, Contract: {} days, Password expires: {} days)",
                employee.getEmail(),
                role.getRoleName(),
                contractDays,
                tempPasswordExpiryDays);

        return savedEmployee;
    }

    /**
     * Extend employee contract
     */
    @Transactional
    public void extendContract(ExtendAccountRequest request, HttpServletRequest httpRequest) {
        User employee = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new ResourceNotFoundException("Employee not found"));

        if (!employee.isEmployee()) {
            throw new IllegalArgumentException("User is not an employee");
        }

        employee.extendAccountExpiry(request.additionalDays());
        userRepository.save(employee);

        // Send notification
        mailService.sendContractExtendedEmail(
                employee.getEmail(),
                employee.getUsername(),
                request.additionalDays(),
                employee.getAccountExpiryDate()
        );

        // Audit log
        auditService.logEvent(
                "CONTRACT_EXTENDED",
                employee,
                true,
                auditService.getClientIp(httpRequest),
                auditService.getUserAgent(httpRequest),
                String.format("Contract extended by %d days, new expiry: %s",
                        request.additionalDays(),
                        employee.getAccountExpiryDate())
        );

        log.info("✓ Extended contract for: {} by {} days (new expiry: {})",
                employee.getEmail(),
                request.additionalDays(),
                employee.getAccountExpiryDate());
    }

    /**
     * Force password change for employee
     */
    @Transactional
    public void forcePasswordChange(String email, HttpServletRequest httpRequest) {
        User employee = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Employee not found"));

        employee.setMustChangePassword(true);
        employee.setCredentialsExpiryDate(LocalDateTime.now().plusDays(7)); // 7 days to change
        userRepository.save(employee);

        mailService.sendPasswordChangeRequired(
                employee.getEmail(),
                employee.getUsername(),
                7
        );

        auditService.logEvent(
                "PASSWORD_CHANGE_FORCED",
                employee,
                true,
                auditService.getClientIp(httpRequest),
                auditService.getUserAgent(httpRequest),
                "Admin forced password change"
        );

        log.info("✓ Forced password change for: {}", email);
    }

    /**
     * Reset employee password (generates new temporary password)
     */
    @Transactional
    public void resetEmployeePassword(String email, HttpServletRequest httpRequest) {
        User employee = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Employee not found"));

        // Generate new temporary password
        String tempPassword = generateTemporaryPassword();
        String encodedPassword = passwordEncoder.encode(tempPassword);

        employee.setPassword(encodedPassword);
        employee.setMustChangePassword(true);
        employee.setPasswordExpiry(tempPasswordExpiryDays);
        userRepository.save(employee);

        // Send email with new password
        mailService.sendPasswordResetByAdmin(
                employee.getEmail(),
                employee.getUsername(),
                tempPassword,
                tempPasswordExpiryDays
        );

        // Audit log
        auditService.logEvent(
                "PASSWORD_RESET_BY_ADMIN",
                employee,
                true,
                auditService.getClientIp(httpRequest),
                auditService.getUserAgent(httpRequest),
                "Admin reset employee password"
        );

        log.info("✓ Reset password for employee: {}", email);
    }

    /**
     * Deactivate employee (end contract early)
     */
    @Transactional
    public void deactivateEmployee(String email, String reason, HttpServletRequest httpRequest) {
        User employee = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Employee not found"));

        if (!employee.isEmployee()) {
            throw new IllegalArgumentException("User is not an employee");
        }

        employee.setEnabled(false);
        employee.setAccountExpiryDate(LocalDateTime.now()); // Expire immediately
        userRepository.save(employee);

        // Send notification
        mailService.sendAccountDeactivatedEmail(
                employee.getEmail(),
                employee.getUsername(),
                reason
        );

        // Audit log
        auditService.logEvent(
                "EMPLOYEE_DEACTIVATED",
                employee,
                true,
                auditService.getClientIp(httpRequest),
                auditService.getUserAgent(httpRequest),
                "Reason: " + reason
        );

        log.warn("🚫 Deactivated employee: {} (Reason: {})", email, reason);
    }

    /**
     * Reactivate employee
     */
    @Transactional
    public void reactivateEmployee(String email, int contractDays, HttpServletRequest httpRequest) {
        User employee = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Employee not found"));

        employee.setEnabled(true);
        employee.setAccountExpiry(contractDays);
        userRepository.save(employee);

        mailService.sendAccountReactivatedEmail(
                employee.getEmail(),
                employee.getUsername(),
                contractDays,
                employee.getAccountExpiryDate()
        );

        auditService.logEvent(
                "EMPLOYEE_REACTIVATED",
                employee,
                true,
                auditService.getClientIp(httpRequest),
                auditService.getUserAgent(httpRequest),
                String.format("Reactivated with %d days contract", contractDays)
        );

        log.info("✓ Reactivated employee: {} ({} days)", email, contractDays);
    }

    /**
     * Get all expiring employee accounts
     */
    @Transactional(readOnly = true)
    public List<User> getExpiringEmployees(int daysThreshold) {
        LocalDateTime threshold = LocalDateTime.now().plusDays(daysThreshold);
        return userRepository.findUsersWithExpiringAccounts(threshold)
                .stream()
                .filter(User::isEmployee)
                .toList();
    }

    /**
     * Generate secure temporary password
     */
    private String generateTemporaryPassword() {
        String uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lowercase = "abcdefghijklmnopqrstuvwxyz";
        String digits = "0123456789";
        String special = "!@#$%^&*";
        String all = uppercase + lowercase + digits + special;

        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder(12);

        // Ensure at least one of each type
        password.append(uppercase.charAt(random.nextInt(uppercase.length())));
        password.append(lowercase.charAt(random.nextInt(lowercase.length())));
        password.append(digits.charAt(random.nextInt(digits.length())));
        password.append(special.charAt(random.nextInt(special.length())));

        // Fill rest randomly
        for (int i = 4; i < 12; i++) {
            password.append(all.charAt(random.nextInt(all.length())));
        }

        // Shuffle
        return shuffleString(password.toString(), random);
    }

    private String shuffleString(String input, SecureRandom random) {
        List<Character> characters = new ArrayList<>();
        for (char c : input.toCharArray()) {
            characters.add(c);
        }
        Collections.shuffle(characters, random);

        StringBuilder result = new StringBuilder();
        for (char c : characters) {
            result.append(c);
        }
        return result.toString();
    }
}