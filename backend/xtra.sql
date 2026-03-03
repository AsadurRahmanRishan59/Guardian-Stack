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
-- Next steps:
-- 1. Change master admin password
-- 2. Update guardian_app_user password
-- 3. Configure application.properties with database credentials
-- 4. Start Spring Boot application
-- 5. Test login with: admin@guardianstack.com / Admin@123

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