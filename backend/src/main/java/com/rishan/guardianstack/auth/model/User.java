package com.rishan.guardianstack.auth.model;

import com.rishan.guardianstack.core.domain.BaseEntity;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.envers.Audited;
import org.hibernate.envers.NotAudited;
import org.hibernate.envers.RelationTargetAuditMode;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "gs_users", indexes = {
        @Index(name = "idx_email", columnList = "email", unique = true),
        @Index(name = "idx_username", columnList = "username"),
        @Index(name = "idx_account_locked", columnList = "account_locked, locked_until"),
        @Index(name = "idx_account_expiry", columnList = "account_expiry_date"),
        @Index(name = "idx_credentials_expiry", columnList = "credentials_expiry_date"),
        @Index(name = "idx_enabled_expiry", columnList = "enabled, account_expiry_date")
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Audited  // ✅ Enable Envers auditing for this entity
public class User extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long userId;

    @Column(nullable = false, unique = true, length = 100)
    private String email;

    @Column(nullable = false, length = 50)
    private String username;

    @Column(nullable = false, length = 255)
    private String password;

    @Column(nullable = false)
    private boolean enabled = false;

    @Enumerated(EnumType.STRING)
    @Column(name = "sign_up_method", length = 20)
    private SignUpMethod signUpMethod;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "gs_user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @Builder.Default
    @Audited(targetAuditMode = RelationTargetAuditMode.NOT_AUDITED)
    // ✅ Audit the relationship AND the target Role entity
    // This tracks when roles are added/removed AND when role details change
    private Set<Role> roles = new HashSet<>();

    // ==========================================
    // ACCOUNT LOCKOUT FIELDS
    // ==========================================
    // ⚠️ IMPORTANT: These fields are NOT audited by Envers because:
    // 1. They change very frequently (every login attempt)
    // 2. They don't represent "business data changes"
    // 3. We already track them via ELK audit logs
    // 4. We update them via native queries to avoid triggering JPA audit
    //
    // If you NEED to audit these for compliance, remove @NotAudited
    // but be prepared for MASSIVE audit table growth!
    // ==========================================

    @Column(name = "failed_login_attempts", nullable = false)
    @Builder.Default
    @NotAudited
    private int failedLoginAttempts = 0;

    @Column(name = "account_locked", nullable = false)
    @Builder.Default
    @NotAudited
    private boolean accountLocked = false;

    @Column(name = "locked_until")
    @NotAudited
    private LocalDateTime lockedUntil;

    @Column(name = "last_failed_login")
    @NotAudited
    private LocalDateTime lastFailedLogin;

    @Column(name = "last_successful_login")
    @NotAudited
    private LocalDateTime lastSuccessfulLogin;

    // ==========================================
    // ACCOUNT EXPIRY FIELDS (IMPORTANT FOR EMPLOYEES)
    // ==========================================
    // ✅ THESE ARE AUDITED because they represent important business events:
    // - Contract start/end dates
    // - Password policy enforcement
    // - Compliance requirements
    // ==========================================

    /**
     * Account expiry date
     * ✅ AUDITED - Important for compliance and contract tracking
     */
    @Column(name = "account_expiry_date")
    private LocalDateTime accountExpiryDate;

    /**
     * Credentials (password) expiry date
     * ✅ AUDITED - Important for security compliance
     */
    @Column(name = "credentials_expiry_date")
    private LocalDateTime credentialsExpiryDate;

    /**
     * Last password change date
     * ✅ AUDITED - Important for security compliance
     */
    @Column(name = "last_password_change")
    private LocalDateTime lastPasswordChange;

    /**
     * Flag to force password change on next login
     * ✅ AUDITED - Important to track when this was set/unset
     */
    @Column(name = "must_change_password", nullable = false)
    @Builder.Default
    private boolean mustChangePassword = false;

    // ==========================================
    // SPRING SECURITY INTERFACE METHODS
    // ==========================================

    /**
     * Checks if account is currently locked.
     * Auto-unlocks if lock period has expired.
     */
    public boolean isAccountNonLocked() {
        if (!accountLocked) {
            return true;
        }

        // Check if lock period has expired
        if (lockedUntil != null && LocalDateTime.now().isAfter(lockedUntil)) {
            // Auto-unlock
            accountLocked = false;
            lockedUntil = null;
            failedLoginAttempts = 0;
            return true;
        }

        return false;
    }

    /**
     * Checks if account has expired
     * Critical for employee/contractor accounts
     */
    public boolean isAccountNonExpired() {
        if (accountExpiryDate == null) {
            return true; // No expiry set (permanent account)
        }

        return LocalDateTime.now().isBefore(accountExpiryDate);
    }

    /**
     * Checks if credentials (password) have expired
     * Critical for security compliance
     */
    public boolean isCredentialsNonExpired() {
        if (credentialsExpiryDate == null) {
            return true; // No expiry set
        }

        return LocalDateTime.now().isBefore(credentialsExpiryDate);
    }

    // ==========================================
    // ACCOUNT LOCKOUT HELPERS
    // ==========================================

    public void incrementFailedAttempts() {
        this.failedLoginAttempts++;
        this.lastFailedLogin = LocalDateTime.now();
    }

    public void resetFailedAttempts() {
        this.failedLoginAttempts = 0;
        this.lastFailedLogin = null;
        this.accountLocked = false;
        this.lockedUntil = null;
        this.lastSuccessfulLogin = LocalDateTime.now();
    }

    public void lockAccount(int lockoutDurationMinutes) {
        this.accountLocked = true;
        this.lockedUntil = LocalDateTime.now().plusMinutes(lockoutDurationMinutes);
    }

    // ==========================================
    // ACCOUNT EXPIRY HELPERS
    // ==========================================

    /**
     * Set account expiry - for employees, contractors, trials
     */
    public void setAccountExpiry(int daysFromNow) {
        this.accountExpiryDate = LocalDateTime.now().plusDays(daysFromNow);
    }

    /**
     * Set password expiry - for temporary passwords, compliance
     */
    public void setPasswordExpiry(int daysFromNow) {
        this.credentialsExpiryDate = LocalDateTime.now().plusDays(daysFromNow);
        this.lastPasswordChange = LocalDateTime.now();
    }

    /**
     * Update password with automatic expiry tracking
     */
    public void updatePassword(String newEncodedPassword, int passwordValidityDays) {
        this.password = newEncodedPassword;
        this.lastPasswordChange = LocalDateTime.now();
        this.mustChangePassword = false; // Reset flag

        if (passwordValidityDays > 0) {
            this.credentialsExpiryDate = LocalDateTime.now().plusDays(passwordValidityDays);
        } else {
            this.credentialsExpiryDate = null; // No expiry
        }
    }

    /**
     * Check if password is about to expire (within warning days)
     */
    public boolean isPasswordExpiringWithinDays(int warningDays) {
        if (credentialsExpiryDate == null) {
            return false;
        }

        LocalDateTime warningDate = LocalDateTime.now().plusDays(warningDays);
        return credentialsExpiryDate.isBefore(warningDate);
    }

    /**
     * Get days until password expires (-1 if no expiry)
     */
    public long getDaysUntilPasswordExpiry() {
        if (credentialsExpiryDate == null) {
            return -1;
        }

        long days = java.time.temporal.ChronoUnit.DAYS.between(
                LocalDateTime.now(),
                credentialsExpiryDate
        );

        return Math.max(0, days); // Don't return negative
    }

    /**
     * Get days until account expires (-1 if no expiry)
     */
    public long getDaysUntilAccountExpiry() {
        if (accountExpiryDate == null) {
            return -1;
        }

        long days = java.time.temporal.ChronoUnit.DAYS.between(
                LocalDateTime.now(),
                accountExpiryDate
        );

        return Math.max(0, days);
    }

    /**
     * Extend account expiry - for contract renewals
     */
    public void extendAccountExpiry(int additionalDays) {
        if (accountExpiryDate == null) {
            this.accountExpiryDate = LocalDateTime.now().plusDays(additionalDays);
        } else {
            // Extend from current expiry date (not from now)
            this.accountExpiryDate = this.accountExpiryDate.plusDays(additionalDays);
        }
    }

    /**
     * Check if user has a specific role
     */
    public boolean hasRole(AppRole role) {
        return roles.stream()
                .anyMatch(r -> r.getRoleName() == role);
    }

    /**
     * Check if user is an employee (not public user)
     */
    public boolean isEmployee() {
        return hasRole(AppRole.ROLE_EMPLOYEE) ||
                hasRole(AppRole.ROLE_ADMIN) ||
                hasRole(AppRole.ROLE_MASTER_ADMIN);
    }

    /**
     * Check if user is public user
     */
    public boolean isPublicUser() {
        return hasRole(AppRole.ROLE_USER) && !isEmployee();
    }
}