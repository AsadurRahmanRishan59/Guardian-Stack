/* =============================================================================
DATABASE: guardian_stack
AUTHOR: Rishan
DATE: 2025-12-25
DESCRIPTION: Core identity and access management (IAM) schema for
             GuardianStack Insurance ERP.
=============================================================================
*/

-- 1. SECURITY: Application User Setup
-- Create a restricted user so the app doesn't run as a Superuser (Admin)
DO
$$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'guardian_app_user') THEN
            CREATE USER guardian_app_user WITH PASSWORD 'SecurePassword123';
        END IF;
    END
$$;

-- 1. First, revoke any broad permissions to start from a clean slate
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM guardian_app_user;

-- 2. GS_USERS: No DELETE allowed
GRANT SELECT, INSERT, UPDATE ON TABLE public.gs_users TO guardian_app_user;
GRANT USAGE, SELECT ON SEQUENCE public.gs_users_user_id_seq TO guardian_app_user;

-- 3. GS_VERIFICATION_TOKENS: Full access (app needs to delete expired tokens)
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.gs_verification_tokens TO guardian_app_user;
GRANT USAGE, SELECT, UPDATE ON SEQUENCE public.gs_verification_tokens_token_id_seq TO guardian_app_user;

-- 4. GS_ROLES: Read-only (The app usually only needs to assign roles, not change them)
GRANT SELECT ON TABLE public.gs_roles TO guardian_app_user;

-- 5. GS_USER_ROLES (Join Table): Full access to link/unlink roles
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.gs_user_roles TO guardian_app_user;

-- 2. TABLES: Identity Management
-- --------------------------------------------------------------------------

-- Table: gs_roles
-- Stores RBAC (Role Based Access Control) levels
CREATE TABLE IF NOT EXISTS public.gs_roles
(
    role_id     SERIAL PRIMARY KEY,
    role_name   VARCHAR(50) NOT NULL UNIQUE,
    description VARCHAR(255),
    CONSTRAINT ck_role_name_format CHECK (role_name LIKE 'ROLE_%') -- Ensures standard Spring prefix
);

COMMENT ON TABLE public.gs_roles IS 'Standardized Spring Security roles for RBAC.';

-- Table: gs_users
-- Core user entity with Spring Security integration flags
CREATE TABLE IF NOT EXISTS public.gs_users
(
    user_id                 BIGSERIAL PRIMARY KEY,
    username                VARCHAR(255) NOT NULL,        -- For display purposes
    email                   VARCHAR(50)  NOT NULL UNIQUE, -- Primary login identifier
    password                VARCHAR(120) NOT NULL,        -- BCrypt Hash

-- Spring Security Status Flags
    account_non_locked      BOOLEAN      NOT NULL DEFAULT TRUE,
    account_non_expired     BOOLEAN      NOT NULL DEFAULT TRUE,
    credentials_non_expired BOOLEAN      NOT NULL DEFAULT TRUE,
    enabled                 BOOLEAN      NOT NULL DEFAULT TRUE,

    -- Expiry Policies
    credentials_expiry_date DATE         NULL,
    account_expiry_date     DATE         NULL,

    -- JPA Auditing / Optimistic Locking
    created_at              TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP    NULL,
    created_by              VARCHAR(50)  NULL,
    updated_by              VARCHAR(50)  NULL,
    version                 BIGINT       NOT NULL DEFAULT 0,

    -- Metadata
    sign_up_method          VARCHAR(50)  NOT NULL DEFAULT 'EMAIL'
);

COMMENT ON COLUMN public.gs_users.password IS 'BCrypt encoded string. Do not store plain text.';
COMMENT ON COLUMN public.gs_users.username IS 'Stores the Full Name or Display Name. Optional during initial signup.';
-- Table: gs_user_roles (Join Table)
-- Handles Many-to-Many relationship between Users and Roles
CREATE TABLE IF NOT EXISTS public.gs_user_roles
(
    user_id BIGINT NOT NULL,
    role_id INT    NOT NULL,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES public.gs_users (user_id) ON DELETE CASCADE,
    CONSTRAINT fk_role FOREIGN KEY (role_id) REFERENCES public.gs_roles (role_id) ON DELETE CASCADE
);

-- 3. INDEXING: Optimization
-- --------------------------------------------------------------------------

-- Faster lookups for Login (Spring Security usually searches by Email)
CREATE INDEX IF NOT EXISTS idx_gs_users_email ON public.gs_users (email);

-- Faster lookups for Joins in Security Filters
CREATE INDEX IF NOT EXISTS idx_gs_user_roles_composite ON public.gs_user_roles (user_id, role_id);


-- 4. PERMISSIONS: Final Application Access
-- --------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO guardian_app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO guardian_app_user;


-- 5. SEED DATA: Initial Roles
-- --------------------------------------------------------------------------
INSERT INTO public.gs_roles (role_name, description)
VALUES ('ROLE_MASTER_ADMIN', 'Full system access and master audit logs'),
       ('ROLE_ADMIN', 'Manage users, settings and general administration'),
       ('ROLE_EMPLOYEE', 'Internal staff processing insurance policies'),
       ('ROLE_USER', 'Public customer purchasing and viewing policies')
ON CONFLICT (role_name) DO NOTHING;

/* =============================================================================
TABLE: gs_verification_tokens
DESCRIPTION: Stores one-time codes for email verification and password resets.
=============================================================================
*/

CREATE TABLE IF NOT EXISTS public.gs_verification_tokens
(
    token_id     BIGSERIAL PRIMARY KEY,
    token        VARCHAR(6)  NOT NULL, -- Storing a 6-digit OTP code
    user_id      BIGINT      NOT NULL,
    token_type   VARCHAR(20) NOT NULL, -- e.g., 'REGISTRATION', 'PASSWORD_RESET'

    -- Expiry Logic
    expiry_date  TIMESTAMP   NOT NULL,
    confirmed_at TIMESTAMP   NULL,     -- When the user actually verified it
    created_at   TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP   NULL,
    created_by   VARCHAR(50) NULL,
    updated_by   VARCHAR(50) NULL,
    version      BIGINT      NOT NULL DEFAULT 0,

    CONSTRAINT fk_token_user FOREIGN KEY (user_id) REFERENCES public.gs_users (user_id) ON DELETE CASCADE
);

-- Index for fast lookup when the user submits the code
CREATE INDEX IF NOT EXISTS idx_gs_token_lookup ON public.gs_verification_tokens (token, user_id);