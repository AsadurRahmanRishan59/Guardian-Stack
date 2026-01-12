package com.rishan.guardianstack.core.logging;

/**
 * Centralized audit event types with ELK-optimized metadata
 * All events logged to Elasticsearch, only critical to PostgreSQL
 */
public enum AuditEventType {

    // ========== AUTHENTICATION EVENTS ==========
    LOGIN_SUCCESS("User logged in successfully", AuditLevel.INFO, LogDestination.ELK_ONLY),
    LOGIN_FAILED("Failed login attempt", AuditLevel.WARN, LogDestination.ELK_AND_DB),
    LOGOUT("User logged out", AuditLevel.INFO, LogDestination.ELK_ONLY),
    LOGOUT_ALL_DEVICES("User logged out from all devices", AuditLevel.INFO, LogDestination.ELK_ONLY),

    // ========== REGISTRATION EVENTS ==========
    SIGNUP_INITIATED("User registration initiated", AuditLevel.INFO, LogDestination.ELK_ONLY),
    SIGNUP_COMPLETED("User registration completed", AuditLevel.INFO, LogDestination.ELK_ONLY),
    SIGNUP_FAILED("Registration attempt failed", AuditLevel.WARN, LogDestination.ELK_AND_DB),

    // ========== VERIFICATION EVENTS ==========
    EMAIL_VERIFIED("Email verified successfully", AuditLevel.INFO, LogDestination.ELK_ONLY),
    EMAIL_VERIFICATION_FAILED("Email verification failed", AuditLevel.WARN, LogDestination.ELK_AND_DB),
    OTP_SENT("Verification OTP sent", AuditLevel.DEBUG, LogDestination.ELK_ONLY),
    OTP_RESENT("Verification OTP resent", AuditLevel.INFO, LogDestination.ELK_ONLY),

    // ========== PASSWORD EVENTS ==========
    PASSWORD_RESET_INITIATED("Password reset initiated", AuditLevel.INFO, LogDestination.ELK_ONLY),
    PASSWORD_RESET_COMPLETED("Password reset completed", AuditLevel.INFO, LogDestination.ELK_AND_DB),
    PASSWORD_RESET_FAILED("Password reset failed", AuditLevel.WARN, LogDestination.ELK_AND_DB),
    PASSWORD_EXPIRY_WARNING("Password expiring soon", AuditLevel.WARN, LogDestination.ELK_ONLY),

    // ========== TOKEN EVENTS ==========
    TOKEN_CREATED("Refresh token created", AuditLevel.DEBUG, LogDestination.ELK_ONLY),
    TOKEN_REFRESHED("Access token refreshed", AuditLevel.DEBUG, LogDestination.ELK_ONLY),
    TOKEN_REVOKED("Token revoked", AuditLevel.INFO, LogDestination.ELK_ONLY),
    TOKEN_REUSE_DETECTED("SECURITY: Token reuse detected", AuditLevel.CRITICAL, LogDestination.ELK_AND_DB),
    TOKEN_EXPIRED("Token expired", AuditLevel.DEBUG, LogDestination.ELK_ONLY),

    // ========== ACCOUNT SECURITY EVENTS ==========
    ACCOUNT_LOCKED("Account locked due to failed attempts", AuditLevel.WARN, LogDestination.ELK_AND_DB),
    ACCOUNT_UNLOCKED("Account unlocked", AuditLevel.INFO, LogDestination.ELK_AND_DB),
    ACCOUNT_EXPIRED("Account expired", AuditLevel.WARN, LogDestination.ELK_AND_DB),
    ACCOUNT_EXPIRY_WARNING("Account expiring soon", AuditLevel.WARN, LogDestination.ELK_ONLY),

    // ========== DEVICE MANAGEMENT ==========
    DEVICE_LIMIT_REACHED("Device limit reached", AuditLevel.INFO, LogDestination.ELK_ONLY),
    DEVICE_REMOVED("Device session removed", AuditLevel.INFO, LogDestination.ELK_ONLY),
    DEVICE_SESSION_REPLACED("Device session replaced", AuditLevel.INFO, LogDestination.ELK_ONLY),

    // ========== ADMIN ACTIONS ==========
    ADMIN_UNLOCK_ACCOUNT("Admin unlocked user account", AuditLevel.INFO, LogDestination.ELK_AND_DB),
    ADMIN_PASSWORD_RESET("Admin reset user password", AuditLevel.WARN, LogDestination.ELK_AND_DB),
    ADMIN_ROLE_CHANGE("Admin changed user roles", AuditLevel.WARN, LogDestination.ELK_AND_DB),

    // ========== SECURITY ALERTS (CRITICAL - Always to DB) ==========
    SUSPICIOUS_ACTIVITY("Suspicious activity detected", AuditLevel.CRITICAL, LogDestination.ELK_AND_DB),
    BRUTE_FORCE_DETECTED("Brute force attack detected", AuditLevel.CRITICAL, LogDestination.ELK_AND_DB),
    UNAUTHORIZED_ACCESS("Unauthorized access attempt", AuditLevel.CRITICAL, LogDestination.ELK_AND_DB),
    RATE_LIMIT_EXCEEDED("Rate limit exceeded", AuditLevel.WARN, LogDestination.ELK_AND_DB);

    private final String description;
    private final AuditLevel level;
    private final LogDestination destination;

    AuditEventType(String description, AuditLevel level, LogDestination destination) {
        this.description = description;
        this.level = level;
        this.destination = destination;
    }

    public String getDescription() { return description; }
    public AuditLevel getLevel() { return level; }
    public LogDestination getDestination() { return destination; }

    public boolean shouldPersistToDatabase() {
        return destination == LogDestination.ELK_AND_DB || destination == LogDestination.DB_ONLY;
    }

    public boolean shouldLogToElasticsearch() {
        return destination == LogDestination.ELK_AND_DB || destination == LogDestination.ELK_ONLY;
    }

    public enum AuditLevel {
        DEBUG,      // Detailed debugging info
        INFO,       // Normal operations
        WARN,       // Warning conditions
        CRITICAL    // Security-critical events
    }

    public enum LogDestination {
        ELK_ONLY,      // Only to Elasticsearch (searchable, queryable)
        ELK_AND_DB,    // Both Elasticsearch AND PostgreSQL (critical events)
        DB_ONLY        // Only to PostgreSQL (rare, used for compliance)
    }
}
