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

