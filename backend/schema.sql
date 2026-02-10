/* =============================================================================
DATABASE: guardian_stack
AUTHOR: Rishan
DATE: 2025-01-05
VERSION: 1.0 - Complete Insurance Schema
DESCRIPTION: Complete identity and access management (IAM) schema for
             GuardianStack Non-Life Insurance ERP with:
             - Role-based multi-device support
             - Account lockout protection
             - Account/credential expiry for employees
             - Token rotation with reuse detection
             - Comprehensive audit logging
             - Insurance regulatory compliance
=============================================================================
*/
-- =============================================================================
-- STEP 1: DATABASE SETUP
-- =============================================================================

-- Create database (run this separately if needed)
CREATE DATABASE guardian_stack;

-- Connect to database
-- \c guardian_stack;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- STEP 2: APPLICATION USER SETUP (Security Best Practice)
-- =============================================================================

-- Create restricted application user (not superuser)
DO
$$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'guardian_app_user') THEN
            CREATE USER guardian_app_user WITH PASSWORD 'SecurePassword123';
            -- Password should be changed in production
        END IF;
    END
$$;
-- =============================================================================
-- STEP 3: CORE TABLES - IDENTITY MANAGEMENT
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Table: gs_roles
-- Purpose: RBAC (Role Based Access Control) for insurance system
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.gs_roles
(
    role_id     SERIAL PRIMARY KEY,
    role_name   VARCHAR(50) NOT NULL UNIQUE,
    description VARCHAR(255),
    created_at  TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT ck_role_name_format CHECK (role_name LIKE 'ROLE_%')
);

COMMENT ON TABLE public.gs_roles IS 'Insurance system roles: MASTER_ADMIN, ADMIN, EMPLOYEE, USER(customer)';
COMMENT ON COLUMN public.gs_roles.role_name IS 'Spring Security role format (ROLE_*)';

-- -----------------------------------------------------------------------------
-- Table: gs_users
-- Purpose: Core user entity with comprehensive security features
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.gs_users
(
    user_id                 BIGSERIAL PRIMARY KEY,
    username                VARCHAR(255) NOT NULL,
    email                   VARCHAR(100) NOT NULL UNIQUE,
    password                VARCHAR(255) NOT NULL,

    -- Basic Flags
    enabled                 BOOLEAN      NOT NULL DEFAULT FALSE,
    sign_up_method          VARCHAR(20)  NOT NULL DEFAULT 'EMAIL',

    -- =========================================================================
    -- ACCOUNT LOCKOUT FIELDS (Brute Force Protection)
    -- =========================================================================
    failed_login_attempts   INTEGER      NOT NULL DEFAULT 0,
    account_locked          BOOLEAN      NOT NULL DEFAULT FALSE,
    locked_until            TIMESTAMP    NULL,
    last_failed_login       TIMESTAMP    NULL,
    last_successful_login   TIMESTAMP    NULL,

    -- =========================================================================
    -- EXPIRY FIELDS (For Employees/Contractors)
    -- =========================================================================
    account_expiry_date     TIMESTAMP    NULL,
    credentials_expiry_date TIMESTAMP    NULL,
    last_password_change    TIMESTAMP    NULL,
    must_change_password    BOOLEAN      NOT NULL DEFAULT FALSE,

    -- =========================================================================
    -- JPA AUDITING (Compliance & Tracking)
    -- =========================================================================
    created_at              TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP    NULL,
    created_by              VARCHAR(50)  NULL,
    updated_by              VARCHAR(50)  NULL,
    version                 BIGINT       NOT NULL DEFAULT 0,

    -- Constraints
    CONSTRAINT ck_email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT ck_sign_up_method CHECK (sign_up_method IN ('EMAIL', 'GOOGLE', 'ADMIN_CREATED', 'MANUAL'))
);

-- Comments for documentation
COMMENT ON TABLE public.gs_users IS 'Core user table with security features: lockout, expiry, audit';
COMMENT ON COLUMN public.gs_users.password IS 'BCrypt encoded password (never plain text)';
COMMENT ON COLUMN public.gs_users.enabled IS 'Account activation status (false until email verified for public users)';
COMMENT ON COLUMN public.gs_users.account_locked IS 'True if locked due to failed login attempts';
COMMENT ON COLUMN public.gs_users.locked_until IS 'Auto-unlock timestamp (30 min default)';
COMMENT ON COLUMN public.gs_users.account_expiry_date IS 'Employee contract end date (NULL for customers)';
COMMENT ON COLUMN public.gs_users.credentials_expiry_date IS 'Password expiry date (90 days for employees)';
COMMENT ON COLUMN public.gs_users.must_change_password IS 'Force password change on next login (temp passwords)';

-- -----------------------------------------------------------------------------
-- Table: gs_user_roles (Many-to-Many Join Table)
-- Purpose: Link users to their roles
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.gs_user_roles
(
    user_id BIGINT  NOT NULL,
    role_id INTEGER NOT NULL,

    PRIMARY KEY (user_id, role_id),

    CONSTRAINT fk_user_roles_user
        FOREIGN KEY (user_id)
            REFERENCES public.gs_users (user_id)
            ON DELETE CASCADE,

    CONSTRAINT fk_user_roles_role
        FOREIGN KEY (role_id)
            REFERENCES public.gs_roles (role_id)
            ON DELETE CASCADE
);

COMMENT ON TABLE public.gs_user_roles IS 'Many-to-many: Users can have multiple roles';

-- =============================================================================
-- STEP 4: VERIFICATION & AUTHENTICATION TABLES
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Table: gs_verification_tokens
-- Purpose: OTP codes for email verification and password reset
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.gs_verification_tokens
(
    token_id              BIGSERIAL PRIMARY KEY,
    token                 VARCHAR(10) NOT NULL,
    user_id               BIGINT      NOT NULL,
    token_type            VARCHAR(20) NOT NULL,

    verified              BOOLEAN     NOT NULL DEFAULT FALSE,
    verified_at           TIMESTAMP   NULL,
    verification_attempts INTEGER     NOT NULL DEFAULT 0,

    expiry_date           TIMESTAMP   NOT NULL,

    -- JPA BaseEntity/Auditing fields
    created_at            TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMP   NULL,
    created_by            VARCHAR(50) NULL,
    updated_by            VARCHAR(50) NULL,
    version               BIGINT      NOT NULL DEFAULT 0,

    CONSTRAINT fk_verification_token_user
        FOREIGN KEY (user_id)
            REFERENCES public.gs_users (user_id)
            ON DELETE CASCADE,

    CONSTRAINT ck_token_type
        CHECK (token_type IN ('EMAIL_VERIFICATION', 'PASSWORD_RESET'))
);

COMMENT ON COLUMN public.gs_verification_tokens.verification_attempts IS 'Counter to prevent brute-forcing OTPs';
-- -----------------------------------------------------------------------------
-- Table: gs_refresh_tokens
-- Purpose: Long-lived refresh tokens with MULTI-DEVICE support
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.gs_refresh_tokens
(
    token_id           BIGSERIAL PRIMARY KEY,
    token              VARCHAR(500) NOT NULL UNIQUE,
    user_id            BIGINT       NOT NULL,

    -- Expiry & Rotation
    expiry_date        TIMESTAMP    NOT NULL,
    created_at         TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- =========================================================================
    -- TOKEN ROTATION & REUSE DETECTION
    -- =========================================================================
    revoked            BOOLEAN      NOT NULL DEFAULT FALSE,
    revoked_at         TIMESTAMP    NULL,
    replaced_by_token  VARCHAR(500) NULL,

    -- =========================================================================
    -- DEVICE TRACKING (Multi-Device Support)
    -- =========================================================================
    ip_address         VARCHAR(45)  NULL,
    user_agent         VARCHAR(500) NULL,
    device_fingerprint VARCHAR(64)  NULL,
    device_name        VARCHAR(100) NULL,

    CONSTRAINT fk_refresh_token_user
        FOREIGN KEY (user_id)
            REFERENCES public.gs_users (user_id)
            ON DELETE CASCADE
);

-- NOTE: Removed UNIQUE constraint on user_id to allow multi-device
COMMENT ON TABLE public.gs_refresh_tokens IS 'Refresh tokens with multi-device support (up to 5 per user)';
COMMENT ON COLUMN public.gs_refresh_tokens.revoked IS 'True when token has been rotated (old token)';
COMMENT ON COLUMN public.gs_refresh_tokens.replaced_by_token IS 'Links to new token (audit trail)';
COMMENT ON COLUMN public.gs_refresh_tokens.device_fingerprint IS 'SHA-256 hash of IP + User-Agent';
COMMENT ON COLUMN public.gs_refresh_tokens.device_name IS 'Parsed device type (iPhone, Windows PC, etc.)';

-- =============================================================================
-- STEP 5: AUDIT LOGGING TABLE
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Table: gs_auth_audit_logs
-- Purpose: Comprehensive security audit trail (7-year retention for insurance)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.gs_auth_audit_logs
(
    id              BIGSERIAL PRIMARY KEY,
    event_type      VARCHAR(50)   NOT NULL,
    user_email      VARCHAR(255)  NULL,
    user_id         BIGINT        NULL,

    -- Request Details
    ip_address      VARCHAR(45)   NULL,
    user_agent      VARCHAR(500)  NULL,

    -- Result
    success         BOOLEAN       NOT NULL DEFAULT FALSE,
    failure_reason  VARCHAR(500)  NULL,
    additional_info VARCHAR(1000) NULL,

    timestamp       TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_audit_log_user
        FOREIGN KEY (user_id)
            REFERENCES public.gs_users (user_id)
            ON DELETE SET NULL
);

COMMENT ON TABLE public.gs_auth_audit_logs IS 'Security audit trail - 7 year retention for insurance compliance';
COMMENT ON COLUMN public.gs_auth_audit_logs.event_type IS 'LOGIN, LOGOUT, TOKEN_REUSE_DETECTED, ACCOUNT_LOCKED, etc.';

-- =============================================================================
-- STEP 6: INDEXES FOR PERFORMANCE
-- =============================================================================

-- Users table indexes
CREATE INDEX IF NOT EXISTS idx_gs_users_email
    ON public.gs_users (email);

CREATE INDEX IF NOT EXISTS idx_gs_users_account_locked
    ON public.gs_users (account_locked, locked_until)
    WHERE account_locked = TRUE;

CREATE INDEX IF NOT EXISTS idx_gs_users_account_expiry
    ON public.gs_users (account_expiry_date)
    WHERE account_expiry_date IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_gs_users_credentials_expiry
    ON public.gs_users (credentials_expiry_date)
    WHERE credentials_expiry_date IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_gs_users_enabled_expiry
    ON public.gs_users (enabled, account_expiry_date);

-- User roles join table
CREATE INDEX IF NOT EXISTS idx_gs_user_roles_user_id
    ON public.gs_user_roles (user_id);

CREATE INDEX IF NOT EXISTS idx_gs_user_roles_role_id
    ON public.gs_user_roles (role_id);

-- Verification tokens
CREATE INDEX IF NOT EXISTS idx_gs_verification_tokens_user_token
    ON public.gs_verification_tokens (user_id, token);

CREATE INDEX IF NOT EXISTS idx_gs_verification_tokens_type_expiry
    ON public.gs_verification_tokens (token_type, expiry_date);

-- Refresh tokens (Critical for multi-device performance)
CREATE INDEX IF NOT EXISTS idx_gs_refresh_tokens_token
    ON public.gs_refresh_tokens (token);

CREATE INDEX IF NOT EXISTS idx_gs_refresh_tokens_user_id
    ON public.gs_refresh_tokens (user_id);

CREATE INDEX IF NOT EXISTS idx_gs_refresh_tokens_revoked
    ON public.gs_refresh_tokens (revoked, revoked_at)
    WHERE revoked = TRUE;

CREATE INDEX IF NOT EXISTS idx_gs_refresh_tokens_device
    ON public.gs_refresh_tokens (user_id, device_fingerprint)
    WHERE revoked = FALSE;

CREATE INDEX IF NOT EXISTS idx_gs_refresh_tokens_expiry
    ON public.gs_refresh_tokens (expiry_date);

CREATE INDEX IF NOT EXISTS idx_gs_refresh_tokens_created
    ON public.gs_refresh_tokens (user_id, created_at);

-- Audit logs (Critical for compliance queries)
CREATE INDEX IF NOT EXISTS idx_gs_auth_audit_logs_user_email
    ON public.gs_auth_audit_logs (user_email);

CREATE INDEX IF NOT EXISTS idx_gs_auth_audit_logs_user_id
    ON public.gs_auth_audit_logs (user_id);

CREATE INDEX IF NOT EXISTS idx_gs_auth_audit_logs_event_type
    ON public.gs_auth_audit_logs (event_type);

CREATE INDEX IF NOT EXISTS idx_gs_auth_audit_logs_timestamp
    ON public.gs_auth_audit_logs (timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_gs_auth_audit_logs_success
    ON public.gs_auth_audit_logs (success);

CREATE INDEX IF NOT EXISTS idx_gs_auth_audit_logs_ip_address
    ON public.gs_auth_audit_logs (ip_address);

-- =============================================================================
-- STEP 7: PERMISSIONS FOR APPLICATION USER
-- =============================================================================

-- Revoke all first (clean slate)
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM guardian_app_user;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM guardian_app_user;

-- Grant table-specific permissions

-- gs_users: No DELETE (soft delete via enabled flag)
GRANT SELECT, INSERT, UPDATE ON TABLE public.gs_users TO guardian_app_user;
GRANT USAGE, SELECT ON SEQUENCE public.gs_users_user_id_seq TO guardian_app_user;

-- gs_roles: Read-only (roles are predefined)
GRANT SELECT ON TABLE public.gs_roles TO guardian_app_user;
GRANT USAGE, SELECT ON SEQUENCE public.gs_roles_role_id_seq TO guardian_app_user;

-- gs_user_roles: Full access (link/unlink roles)
GRANT SELECT, INSERT, DELETE ON TABLE public.gs_user_roles TO guardian_app_user;

-- gs_verification_tokens: Full access (cleanup expired tokens)
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.gs_verification_tokens TO guardian_app_user;
GRANT USAGE, SELECT ON SEQUENCE public.gs_verification_tokens_token_id_seq TO guardian_app_user;

-- gs_refresh_tokens: Full access (multi-device management)
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.gs_refresh_tokens TO guardian_app_user;
GRANT USAGE, SELECT ON SEQUENCE public.gs_refresh_tokens_token_id_seq TO guardian_app_user;

-- gs_auth_audit_logs: Insert-only (append-only audit trail)
GRANT SELECT, INSERT ON TABLE public.gs_auth_audit_logs TO guardian_app_user;
GRANT USAGE, SELECT ON SEQUENCE public.gs_auth_audit_logs_id_seq TO guardian_app_user;

-- =============================================================================
-- STEP 8: SEED DATA - ROLES
-- =============================================================================
INSERT INTO public.gs_roles (role_name, description)
VALUES ('ROLE_MASTER_ADMIN',
        'Super-user with unrestricted access to system configuration, underwriting rules, and global financial reporting. Managed under strict single-device security policy.'),

       ('ROLE_ADMIN',
        'Administrative lead responsible for regional staff management, user credential oversight, and operational auditing. Permitted for dual-device office/remote mobility.'),

       ('ROLE_EMPLOYEE',
        'Operational staff authorized for policy verification, claims processing support, and customer relationship management. Restricted to authorized work-hour access.'),

       ('ROLE_USER',
        'Policyholder account with self-service capabilities for premium payments, policy downloads, and claims intimation. Optimized for multi-device consumer access.')
ON CONFLICT (role_name) DO UPDATE
    SET description = EXCLUDED.description;

-- =============================================================================
-- STEP 9: SEED DATA - MASTER ADMIN USER
-- =============================================================================

-- Password: Admin@123 (CHANGE THIS IN PRODUCTION!)
-- BCrypt hash generated with strength 12
INSERT INTO public.gs_users (username,
                             email,
                             password,
                             enabled,
                             sign_up_method,
                             created_by)
VALUES ('Rishan Master Admin',
        'admin@guardianstack.com',
        '$2a$12$OZKeDs.9l9Q0ldUmRfnhteUWaveBGuZnU6dr1qx04hCXQ4B05shMy', -- Admin@123
        TRUE,
        'MANUAL',
        'SYSTEM')
ON CONFLICT (email) DO NOTHING;

-- Link to MASTER_ADMIN role
INSERT INTO public.gs_user_roles (user_id, role_id)
SELECT u.user_id,
       r.role_id
FROM public.gs_users u
         CROSS JOIN public.gs_roles r
WHERE u.email = 'admin@guardianstack.com'
  AND r.role_name = 'ROLE_MASTER_ADMIN'
ON CONFLICT DO NOTHING;

-- =============================================================================
-- STEP 10: UTILITY VIEWS (Insurance Monitoring)
-- =============================================================================

-- View: Active sessions per user (device management)
CREATE OR REPLACE VIEW v_active_sessions AS
SELECT u.user_id,
       u.username,
       u.email,
       r.role_name,
       COUNT(rt.token_id)               as active_devices,
       STRING_AGG(rt.device_name, ', ') as devices,
       MAX(rt.created_at)               as last_login
FROM public.gs_users u
         LEFT JOIN public.gs_user_roles ur ON u.user_id = ur.user_id
         LEFT JOIN public.gs_roles r ON ur.role_id = r.role_id
         LEFT JOIN public.gs_refresh_tokens rt ON u.user_id = rt.user_id
    AND rt.revoked = FALSE
    AND rt.expiry_date > NOW()
GROUP BY u.user_id, u.username, u.email, r.role_name;

COMMENT ON VIEW v_active_sessions IS 'Monitor active user sessions across devices';

-- View: Expiring employee contracts (next 30 days)
CREATE OR REPLACE VIEW v_expiring_employee_contracts AS
SELECT u.user_id,
       u.username,
       u.email,
       u.account_expiry_date,
       EXTRACT(DAY FROM (u.account_expiry_date - NOW())) as days_remaining,
       r.role_name
FROM public.gs_users u
         JOIN public.gs_user_roles ur ON u.user_id = ur.user_id
         JOIN public.gs_roles r ON ur.role_id = r.role_id
WHERE u.account_expiry_date IS NOT NULL
  AND u.account_expiry_date BETWEEN NOW() AND NOW() + INTERVAL '30 days'
  AND u.enabled = TRUE
  AND r.role_name IN ('ROLE_EMPLOYEE', 'ROLE_ADMIN')
ORDER BY u.account_expiry_date;

COMMENT ON VIEW v_expiring_employee_contracts IS 'Employee contracts expiring in next 30 days';

-- View: Expiring passwords (next 14 days)
CREATE OR REPLACE VIEW v_expiring_passwords AS
SELECT u.user_id,
       u.username,
       u.email,
       u.credentials_expiry_date,
       EXTRACT(DAY FROM (u.credentials_expiry_date - NOW())) as days_remaining,
       u.last_password_change,
       r.role_name
FROM public.gs_users u
         JOIN public.gs_user_roles ur ON u.user_id = ur.user_id
         JOIN public.gs_roles r ON ur.role_id = r.role_id
WHERE u.credentials_expiry_date IS NOT NULL
  AND u.credentials_expiry_date BETWEEN NOW() AND NOW() + INTERVAL '14 days'
  AND u.enabled = TRUE
ORDER BY u.credentials_expiry_date;

COMMENT ON VIEW v_expiring_passwords IS 'Passwords expiring in next 14 days';

-- View: Locked accounts
CREATE OR REPLACE VIEW v_locked_accounts AS
SELECT u.user_id,
       u.username,
       u.email,
       u.failed_login_attempts,
       u.locked_until,
       u.last_failed_login,
       CASE
           WHEN u.locked_until > NOW() THEN 'LOCKED'
           ELSE 'LOCK_EXPIRED'
           END                                       as lock_status,
       EXTRACT(MINUTE FROM (u.locked_until - NOW())) as minutes_until_unlock
FROM public.gs_users u
WHERE u.account_locked = TRUE
ORDER BY u.locked_until DESC;

COMMENT ON VIEW v_locked_accounts IS 'Currently locked accounts and auto-unlock times';

-- View: Recent security events (last 7 days)
CREATE OR REPLACE VIEW v_recent_security_events AS
SELECT event_type,
       user_email,
       ip_address,
       success,
       failure_reason,
       timestamp,
       COUNT(*) OVER (PARTITION BY user_email, DATE(timestamp)) as daily_events
FROM public.gs_auth_audit_logs
WHERE timestamp > NOW() - INTERVAL '7 days'
  AND event_type IN ('LOGIN', 'LOGOUT', 'TOKEN_REUSE_DETECTED', 'ACCOUNT_LOCKED')
ORDER BY timestamp DESC;

COMMENT ON VIEW v_recent_security_events IS 'Security-related events from last 7 days';

-- =============================================================================
-- STEP 11: PERFORMANCE OPTIMIZATION
-- =============================================================================

-- Update statistics for query planner
ANALYZE public.gs_users;
ANALYZE public.gs_roles;
ANALYZE public.gs_user_roles;
ANALYZE public.gs_verification_tokens;
ANALYZE public.gs_refresh_tokens;
ANALYZE public.gs_auth_audit_logs;

-- Enable auto-vacuum for large tables (audit logs)
ALTER TABLE public.gs_auth_audit_logs
    SET (
        autovacuum_enabled = true,
        autovacuum_vacuum_scale_factor = 0.1,
        autovacuum_analyze_scale_factor = 0.05
        );

-- =============================================================================
-- STEP 12: VERIFICATION QUERIES
-- =============================================================================

-- Verify all tables exist
SELECT schemaname,
       tablename,
       pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename)) as size
FROM pg_tables
WHERE schemaname = 'public'
  AND tablename LIKE 'gs_%'
ORDER BY tablename;

-- Verify all indexes exist
SELECT schemaname,
       tablename,
       indexname
FROM pg_indexes
WHERE schemaname = 'public'
  AND tablename LIKE 'gs_%'
ORDER BY tablename, indexname;

-- Verify roles
SELECT *
FROM public.gs_roles
ORDER BY role_id;

-- Verify master admin user
SELECT u.user_id,
       u.username,
       u.email,
       u.enabled,
       r.role_name
FROM public.gs_users u
         LEFT JOIN public.gs_user_roles ur ON u.user_id = ur.user_id
         LEFT JOIN public.gs_roles r ON ur.role_id = r.role_id
WHERE u.email = 'admin@guardianstack.com';

-- =============================================================================
-- SCRIPT COMPLETE
-- =============================================================================

SELECT '✅ GuardianStack Insurance Database Setup Complete!' as status,
       NOW()                                                as completed_at;

-- Next steps:
-- 1. Change master admin password
-- 2. Update guardian_app_user password
-- 3. Configure application.properties with database credentials
-- 4. Start Spring Boot application
-- 5. Test login with: admin@guardianstack.com / Admin@123

-- =========================================================================
-- HIBERNATE ENVERS AUDIT TABLES FOR gs_users
-- =========================================================================
-- These tables track ALL changes to user records with full history
-- Envers creates two tables: _AUD (audit data) and REVINFO (revision metadata)
-- =========================================================================

-- =========================================================================
-- 1. REVISION INFO TABLE (Shared across all audited entities)
-- =========================================================================
-- This table stores metadata about each revision (who, when, what type)
-- One revision can contain changes to multiple entities
-- =========================================================================

CREATE TABLE IF NOT EXISTS public.revinfo
(
    rev      BIGSERIAL PRIMARY KEY,
    revtstmp BIGINT NOT NULL,  -- Timestamp in milliseconds (Unix epoch)

    -- Custom fields (optional - add if you want to track who made the change)
    username VARCHAR(255) NULL,  -- Who made the change
    ip_address VARCHAR(45) NULL  -- IP address of the user
);

-- Index for timestamp queries (common use case: "show me changes in last 30 days")
CREATE INDEX IF NOT EXISTS idx_revinfo_revtstmp ON public.revinfo(revtstmp);

COMMENT ON TABLE public.revinfo IS 'Envers revision metadata - tracks when and by whom changes were made';
COMMENT ON COLUMN public.revinfo.rev IS 'Unique revision ID - auto-incremented for each transaction';
COMMENT ON COLUMN public.revinfo.revtstmp IS 'Revision timestamp in milliseconds since Unix epoch';
COMMENT ON COLUMN public.revinfo.username IS 'Username who made the change (custom field)';
COMMENT ON COLUMN public.revinfo.ip_address IS 'IP address from where change was made (custom field)';

-- =========================================================================
-- 2. USER AUDIT TABLE (Stores historical versions of user records)
-- =========================================================================
-- This table is a mirror of gs_users with additional audit columns
-- Every time a user record is created, updated, or deleted, a new row is added here
-- =========================================================================

CREATE TABLE IF NOT EXISTS public.gs_users_aud
(
    -- =========================================================================
    -- PRIMARY KEY (Composite: user_id + rev)
    -- =========================================================================
    user_id                 BIGINT       NOT NULL,  -- References gs_users.user_id
    rev                     BIGINT       NOT NULL,  -- References revinfo.rev

    -- =========================================================================
    -- REVISION TYPE (What happened in this revision?)
    -- =========================================================================
    revtype                 SMALLINT     NOT NULL,  -- 0=INSERT, 1=UPDATE, 2=DELETE

    -- =========================================================================
    -- AUDITED FIELDS (All fields from gs_users that we want to track)
    -- =========================================================================

    -- Basic User Info
    username                VARCHAR(255) NULL,
    email                   VARCHAR(100) NULL,
    password                VARCHAR(255) NULL,

    -- Basic Flags
    enabled                 BOOLEAN      NULL,
    sign_up_method          VARCHAR(20)  NULL,

    -- =========================================================================
    -- ACCOUNT LOCKOUT FIELDS (Track security events)
    -- =========================================================================
    failed_login_attempts   INTEGER      NULL,
    account_locked          BOOLEAN      NULL,
    locked_until            TIMESTAMP    NULL,
    last_failed_login       TIMESTAMP    NULL,
    last_successful_login   TIMESTAMP    NULL,

    -- =========================================================================
    -- EXPIRY FIELDS (Track changes to expiry dates)
    -- =========================================================================
    account_expiry_date     TIMESTAMP    NULL,
    credentials_expiry_date TIMESTAMP    NULL,
    last_password_change    TIMESTAMP    NULL,
    must_change_password    BOOLEAN      NULL,

    -- =========================================================================
    -- JPA AUDITING (Track when metadata changed)
    -- =========================================================================
    created_at              TIMESTAMP    NULL,
    updated_at              TIMESTAMP    NULL,
    created_by              VARCHAR(50)  NULL,
    updated_by              VARCHAR(50)  NULL,
    version                 BIGINT       NULL,

    -- =========================================================================
    -- CONSTRAINTS
    -- =========================================================================
    PRIMARY KEY (user_id, rev),
    CONSTRAINT fk_gs_users_aud_rev FOREIGN KEY (rev)
        REFERENCES public.revinfo(rev) ON DELETE CASCADE
);

-- =========================================================================
-- INDEXES FOR COMMON AUDIT QUERIES
-- =========================================================================

-- Query: "Show me all changes to user X"
CREATE INDEX IF NOT EXISTS idx_gs_users_aud_user_id
    ON public.gs_users_aud(user_id);

-- Query: "Show me all changes in revision Y"
CREATE INDEX IF NOT EXISTS idx_gs_users_aud_rev
    ON public.gs_users_aud(rev);

-- Query: "Show me all user deletions"
CREATE INDEX IF NOT EXISTS idx_gs_users_aud_revtype
    ON public.gs_users_aud(revtype);

-- Query: "Show me changes to email addresses"
CREATE INDEX IF NOT EXISTS idx_gs_users_aud_email
    ON public.gs_users_aud(email);

-- Query: "Show me when accounts were locked"
CREATE INDEX IF NOT EXISTS idx_gs_users_aud_account_locked
    ON public.gs_users_aud(account_locked)
    WHERE account_locked = TRUE;

-- Query: "Show me password changes" (when last_password_change was modified)
CREATE INDEX IF NOT EXISTS idx_gs_users_aud_last_password_change
    ON public.gs_users_aud(last_password_change);

-- =========================================================================
-- COMMENTS FOR DOCUMENTATION
-- =========================================================================

COMMENT ON TABLE public.gs_users_aud IS 'Envers audit table - stores complete history of all changes to gs_users table';
COMMENT ON COLUMN public.gs_users_aud.user_id IS 'User ID from gs_users table';
COMMENT ON COLUMN public.gs_users_aud.rev IS 'Revision ID from revinfo table';
COMMENT ON COLUMN public.gs_users_aud.revtype IS 'Type of change: 0=INSERT (new user), 1=UPDATE (modified user), 2=DELETE (deleted user)';

-- =========================================================================
-- EXAMPLE QUERIES
-- =========================================================================

-- Query 1: Get all changes for a specific user
-- SELECT u.*, r.revtstmp, r.username as changed_by
-- FROM gs_users_aud u
-- JOIN revinfo r ON u.rev = r.rev
-- WHERE u.user_id = 123
-- ORDER BY r.revtstmp DESC;

-- Query 2: Get all email changes
-- SELECT u.user_id, u.email, r.revtstmp
-- FROM gs_users_aud u
-- JOIN revinfo r ON u.rev = r.rev
-- WHERE u.revtype = 1  -- UPDATE only
-- ORDER BY r.revtstmp DESC;

-- Query 3: Get all account lockouts in last 30 days
-- SELECT u.user_id, u.email, u.locked_until, r.revtstmp
-- FROM gs_users_aud u
-- JOIN revinfo r ON u.rev = r.rev
-- WHERE u.account_locked = TRUE
--   AND u.revtype = 1
--   AND r.revtstmp >= EXTRACT(EPOCH FROM NOW() - INTERVAL '30 days') * 1000
-- ORDER BY r.revtstmp DESC;

-- Query 4: Get password change history for compliance
-- SELECT u.user_id, u.email, u.last_password_change, r.revtstmp, r.username
-- FROM gs_users_aud u
-- JOIN revinfo r ON u.rev = r.rev
-- WHERE u.last_password_change IS NOT NULL
--   AND u.revtype = 1
-- ORDER BY u.user_id, r.revtstmp DESC;

-- Query 5: Track who enabled/disabled accounts
-- SELECT u.user_id, u.email, u.enabled, r.username as changed_by, r.revtstmp
-- FROM gs_users_aud u
-- JOIN revinfo r ON u.rev = r.rev
-- WHERE u.revtype = 1
-- ORDER BY r.revtstmp DESC;

-- =========================================================================
-- DATA RETENTION POLICY (Optional - uncomment if needed)
-- =========================================================================

-- Delete audit records older than 7 years (regulatory compliance)
-- Run this as a scheduled job (e.g., once per month)
/*
DELETE FROM gs_users_aud
WHERE rev IN (
    SELECT rev FROM revinfo
    WHERE revtstmp < EXTRACT(EPOCH FROM NOW() - INTERVAL '7 years') * 1000
);

DELETE FROM revinfo
WHERE revtstmp < EXTRACT(EPOCH FROM NOW() - INTERVAL '7 years') * 1000;
*/

-- =========================================================================
-- HIBERNATE ENVERS AUDIT TABLE FOR JOIN TABLE (gs_user_roles)
-- =========================================================================
-- This table is required because we're using:
-- @Audited(targetAuditMode = RelationTargetAuditMode.RELATION_AND_TARGET)
-- on the User.roles relationship
--
-- This tracks when roles are added/removed from users
-- =========================================================================

CREATE TABLE IF NOT EXISTS public.gs_user_roles_aud
(
    -- =========================================================================
    -- REVISION INFO
    -- =========================================================================
    rev                     BIGINT       NOT NULL,  -- References revinfo.rev
    revtype                 SMALLINT     NOT NULL,  -- 0=INSERT, 1=UPDATE, 2=DELETE

    -- =========================================================================
    -- JOIN TABLE COLUMNS (from gs_user_roles)
    -- =========================================================================
    user_id                 BIGINT       NOT NULL,  -- User ID
    role_id                 INTEGER      NOT NULL,  -- Role ID (INTEGER to match your Role entity)

    -- =========================================================================
    -- CONSTRAINTS
    -- =========================================================================
    PRIMARY KEY (user_id, role_id, rev),

    CONSTRAINT fk_gs_user_roles_aud_rev
        FOREIGN KEY (rev) REFERENCES public.revinfo(rev) ON DELETE CASCADE
);

-- =========================================================================
-- INDEXES FOR COMMON QUERIES
-- =========================================================================

-- Query: "Show me all role changes for a user"
CREATE INDEX IF NOT EXISTS idx_gs_user_roles_aud_user_id
    ON public.gs_user_roles_aud(user_id);

-- Query: "Show me all users who had a specific role"
CREATE INDEX IF NOT EXISTS idx_gs_user_roles_aud_role_id
    ON public.gs_user_roles_aud(role_id);

-- Query: "Show me all role changes in a specific revision"
CREATE INDEX IF NOT EXISTS idx_gs_user_roles_aud_rev
    ON public.gs_user_roles_aud(rev);

-- Query: "Show me when roles were added vs removed"
CREATE INDEX IF NOT EXISTS idx_gs_user_roles_aud_revtype
    ON public.gs_user_roles_aud(revtype);

-- =========================================================================
-- COMMENTS
-- =========================================================================

COMMENT ON TABLE public.gs_user_roles_aud IS
    'Envers audit table for gs_user_roles join table - tracks role assignments and removals';

COMMENT ON COLUMN public.gs_user_roles_aud.rev IS
    'Revision ID from revinfo table';

COMMENT ON COLUMN public.gs_user_roles_aud.revtype IS
    'Type of change: 0=INSERT (role assigned), 2=DELETE (role removed)';

COMMENT ON COLUMN public.gs_user_roles_aud.user_id IS
    'User ID from gs_users table';

COMMENT ON COLUMN public.gs_user_roles_aud.role_id IS
    'Role ID from gs_roles table';

-- =========================================================================
-- EXAMPLE QUERIES
-- =========================================================================

-- Query 1: Get all role assignments/removals for a user
-- SELECT ur.*, r.revtstmp, r.username as changed_by, r.ip_address
-- FROM gs_user_roles_aud ur
-- JOIN revinfo r ON ur.rev = r.rev
-- WHERE ur.user_id = 123
-- ORDER BY r.revtstmp DESC;

-- Query 2: Find when a user was given ADMIN role
-- SELECT ur.user_id, ur.role_id, r.revtstmp, r.username
-- FROM gs_user_roles_aud ur
-- JOIN revinfo r ON ur.rev = r.rev
-- JOIN gs_roles gr ON ur.role_id = gr.role_id
-- WHERE ur.user_id = 123
--   AND gr.role_name = 'ROLE_ADMIN'
--   AND ur.revtype = 0  -- INSERT (role was added)
-- ORDER BY r.revtstmp DESC;

-- Query 3: Find when a user's admin role was revoked
-- SELECT ur.user_id, ur.role_id, r.revtstmp, r.username
-- FROM gs_user_roles_aud ur
-- JOIN revinfo r ON ur.rev = r.rev
-- JOIN gs_roles gr ON ur.role_id = gr.role_id
-- WHERE ur.user_id = 123
--   AND gr.role_name = 'ROLE_ADMIN'
--   AND ur.revtype = 2  -- DELETE (role was removed)
-- ORDER BY r.revtstmp DESC;

-- Query 4: Get all users who had ADMIN role at any point
-- SELECT DISTINCT ur.user_id, u.email, u.username
-- FROM gs_user_roles_aud ur
-- JOIN gs_users u ON ur.user_id = u.user_id
-- JOIN gs_roles gr ON ur.role_id = gr.role_id
-- WHERE gr.role_name = 'ROLE_ADMIN'
--   AND ur.revtype = 0;  -- Only assignments, not removals

-- Query 5: Track privilege escalation (when non-admins became admins)
-- SELECT
--     ur.user_id,
--     u.email,
--     r.revtstmp,
--     r.username as granted_by,
--     r.ip_address
-- FROM gs_user_roles_aud ur
-- JOIN revinfo r ON ur.rev = r.rev
-- JOIN gs_users u ON ur.user_id = u.user_id
-- JOIN gs_roles gr ON ur.role_id = gr.role_id
-- WHERE gr.role_name IN ('ROLE_ADMIN', 'ROLE_MASTER_ADMIN')
--   AND ur.revtype = 0  -- Role was added
-- ORDER BY r.revtstmp DESC;