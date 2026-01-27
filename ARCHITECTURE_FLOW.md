# GuardianStack: Frontend → BFF → Backend → Database Flow

## Architecture Overview

GuardianStack follows a **3-tier architecture with a BFF (Backend for Frontend) pattern**:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          FRONTEND (Port 4000)                           │
│                     Next.js 16 + React 19 + TailwindCSS                │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
                      HTTP/HTTPS with Credentials
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│           BFF LAYER (Port 4000 - Next.js API Routes)                   │
│                    (/api/* endpoints)                                   │
│  - JWT Token Encryption/Decryption                                      │
│  - CSRF Token Management                                                │
│  - Cookie Handling (httpOnly, Secure)                                   │
│  - Request/Response Transformation                                      │
│  - Error Handling & Rate Limiting                                       │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
                    HTTP with Bearer Token Header
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│              BACKEND (Port 6060)                                        │
│          Spring Boot 4.0.1 + Java 21 + PostgreSQL                      │
│                     /api/* endpoints                                    │
│  - Authentication & Authorization (JWT)                                 │
│  - Role-Based Access Control (RBAC)                                     │
│  - Business Logic & Validation                                          │
│  - Audit Logging (ELK Stack)                                            │
│  - Email Service                                                        │
│  - Rate Limiting                                                        │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
                          SQL Queries (JDBC)
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│                     DATABASE (PostgreSQL)                               │
│              Tables: gs_users, gs_roles, gs_tokens, etc.               │
│                  Elasticsearch (Audit Logs)                            │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Flow Breakdown

### 1. FRONTEND LAYER (Next.js - Port 4000)

**Key Components:**
- [lib/api/api-client.ts](lib/api/api-client.ts) - HTTP client wrapper
- [lib/api/auth.service.ts](lib/api/auth.service.ts) - Authentication service
- [lib/api/crypto.ts](lib/api/crypto.ts) - Token encryption/decryption

**Flow Example: Login Request**

```typescript
// User clicks login on React component
const response = await authService.login({ email, password });

// authService.login() calls:
apiClient.post('/api/auth/login', credentials);

// apiClient.post() makes HTTP request to:
POST /api/auth/login
Content-Type: application/json
Credentials: include

{
  "email": "user@example.com",
  "password": "password123"
}
```

---

### 2. BFF LAYER (Next.js API Routes - Port 4000)

**Key Files:**
- [app/api/auth/signin/route.ts](app/api/auth/signin/route.ts)
- [app/api/auth/me/route.ts](app/api/auth/me/route.ts)
- [app/api/auth/logout/route.ts](app/api/auth/logout/route.ts)
- [app/api/admin/roles/route.ts](app/api/admin/roles/route.ts)
- [app/api/admin/user/route.ts](app/api/admin/user/route.ts)

**Responsibilities:**
1. **Receive Frontend Request** → `/api/auth/signin`
2. **Forward to Backend** → `http://localhost:6060/api/auth/public/signin`
3. **Receive JWT from Backend**
4. **Encrypt JWT Token** using AES encryption
5. **Set Secure Cookies:**
   - `jwt_token`: httpOnly, encrypted (server-side only)
   - `XSRF-TOKEN`: readable by browser JS for CSRF protection
6. **Return Response** to frontend

**Example: Sign-in Route Flow**

```typescript
// app/api/auth/signin/route.ts

POST /api/auth/signin
↓
1. Extract credentials from request body
   { email, password }
↓
2. Forward to backend Spring Boot:
   POST http://localhost:6060/api/auth/public/signin
   Body: { email, password }
↓
3. Backend returns:
   {
     "success": true,
     "data": {
       "jwtToken": "eyJhbGciOiJIUzI1NiIs...",
       "refreshToken": "...",
       "user": { id, email, roles }
     }
   }
↓
4. BFF encrypts JWT:
   encryptedJwt = encryptToken(jwtToken)
↓
5. BFF sets cookies:
   Set-Cookie: jwt_token=<encrypted>; HttpOnly; Secure; SameSite=Lax
   Set-Cookie: XSRF-TOKEN=<uuid>; HttpOnly=false; SameSite=Lax
↓
6. Return to frontend:
   {
     "success": true,
     "data": { user, refreshToken }
   }
```

---

### 3. BACKEND LAYER (Spring Boot - Port 6060)

**Architecture: Layered Pattern**

```
┌─────────────────────────────────┐
│      REST Controllers           │
│  (Handle HTTP Requests)         │
└────────────┬────────────────────┘
             ↓
┌─────────────────────────────────┐
│      Service Layer              │
│  (Business Logic)               │
└────────────┬────────────────────┘
             ↓
┌─────────────────────────────────┐
│      Repository/DAO             │
│  (Database Access via JPA)       │
└────────────┬────────────────────┘
             ↓
┌─────────────────────────────────┐
│      Entity Models              │
│  (JPA Entities)                 │
└─────────────────────────────────┘
```

**Key Packages:**

#### a) Auth Module (`com.rishan.guardianstack.auth`)

**Controllers:**
- [AuthController.java](backend/src/main/java/com/rishan/guardianstack/auth/controller/AuthController.java)
  - `POST /auth/public/signup` - Register new user
  - `POST /auth/public/verify-otp` - Verify OTP
  - `POST /auth/public/signin` - Login
  - `POST /auth/refresh-token` - Refresh JWT
  - `GET /auth/me` - Get current user
  - `POST /auth/logout` - Logout

- [SessionManagementController.java](backend/src/main/java/com/rishan/guardianstack/auth/controller/SessionManagementController.java)
  - `GET /sessions` - List user sessions
  - `DELETE /sessions/{tokenId}` - Logout from specific device
  - `DELETE /sessions/revoke-others` - Logout from all other devices

**Services:**
- `AuthServiceImpl` - Core auth logic
  - User registration
  - Email verification (OTP)
  - JWT token generation
  - Account lockout after failed attempts
  - Password reset flow

- `RefreshTokenServiceImpl` - Token management
  - Store refresh tokens
  - Detect token reuse (security feature)
  - Refresh JWT tokens

- `MailServiceImpl` - Email notifications
  - Send OTP
  - Password reset emails

**Entities/Models:**
- `GsUser` - Core user entity
- `GsRole` - Role definitions
- `RefreshToken` - Token storage
- `VerificationToken` - OTP storage

#### b) Admin Module (`com.rishan.guardianstack.admin`)

**Controllers:**
- [AdminController.java](backend/src/main/java/com/rishan/guardianstack/admin/controller/AdminController.java)
  - `POST /admin/users` - Create employee user
  - `POST /admin/extend-contract` - Extend employee contract
  - `POST /admin/force-password-change` - Force password reset
  - `POST /admin/deactivate` - Deactivate user
  - `POST /admin/reactivate` - Reactivate user
  - `GET /admin/expiring` - List expiring accounts

#### c) Master Admin Module (`com.rishan.guardianstack.masteradmin`)

**Controllers:**
- [MasterAdminUserController.java](backend/src/main/java/com/rishan/guardianstack/masteradmin/user/controller/MasterAdminUserController.java)
  - `GET /master-admin/users` - List all users
  - `GET /master-admin/users/{userId}` - Get user details
  - `POST /master-admin/users` - Create user
  - `PUT /master-admin/users/{userId}` - Update user
  - `DELETE /master-admin/users/{userId}` - Delete user

#### d) Core Module (`com.rishan.guardianstack.core`)

**Features:**
- **Exception Handling:** [GlobalExceptionHandler.java](backend/src/main/java/com/rishan/guardianstack/core/exception/GlobalExceptionHandler.java)
  - Centralized error handling
  - Consistent error responses

- **Security:**
  - JWT Token validation
  - RBAC Authorization
  - Rate Limiting decorator (`@RateLimited`)

- **Audit Logging:**
  - [ELKAuditService](backend/src/main/java/com/rishan/guardianstack/auth/service/ELKAuditService.java)
  - Logs to Elasticsearch
  - Async processing (thread pool)
  - Compliance tracking

---

### 4. DATABASE LAYER (PostgreSQL)

**Location:** `localhost:5432/guardian_stack`
**Schema File:** [backend/schema.sql](backend/schema.sql)

**Core Tables:**

#### Identity & Access Management

```sql
-- Roles for RBAC
gs_roles (
  role_id (PK),
  role_name: ROLE_MASTER_ADMIN, ROLE_ADMIN, ROLE_EMPLOYEE, ROLE_USER,
  description,
  created_at
)

-- Users
gs_users (
  user_id (PK),
  username,
  email (UNIQUE),
  password (bcrypt hashed),
  enabled,
  sign_up_method: EMAIL | SSO,
  
  -- Account Lockout (Brute Force Protection)
  failed_login_attempts,
  account_locked,
  locked_until,
  last_failed_login,
  last_successful_login,
  
  -- Expiry (Employee/Contractor)
  account_expiry_date,
  credentials_expiry_date,
  last_password_change,
  must_change_password,
  
  -- Audit
  created_by,
  created_at,
  modified_by,
  modified_at
)

-- User-Role Mapping (Many-to-Many)
gs_user_roles (
  user_id (FK),
  role_id (FK)
)

-- JWT Refresh Tokens
gs_refresh_tokens (
  token_id (PK),
  user_id (FK),
  token_value (hashed),
  expiry_date,
  revoked,
  created_at,
  device_info (for multi-device support)
)

-- Email Verification Tokens (OTP)
gs_verification_tokens (
  token_id (PK),
  user_id (FK),
  token_value (hashed),
  token_type: EMAIL_VERIFICATION | PASSWORD_RESET,
  expiry_date,
  used,
  created_at
)
```

**Elasticsearch Integration:**
```
Index: audit-logs
Fields:
  - timestamp
  - user_id
  - action: LOGIN, LOGOUT, CREATE_USER, DELETE_USER, etc.
  - status: SUCCESS, FAILURE
  - ip_address
  - user_agent
  - details (JSON)
```

---

## Complete Request/Response Flow Example: Login

### 1️⃣ Frontend → BFF

```
POST http://localhost:4000/api/auth/signin
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123"
}
```

### 2️⃣ BFF → Backend

```
POST http://localhost:6060/api/auth/public/signin
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123"
}
```

### 3️⃣ Backend Processing

```
AuthController.signin()
  ↓
AuthServiceImpl.authenticateUser()
  ├─ UserRepository.findByEmail() → GsUser entity
  ├─ Check: account_locked, account_enabled, expiry dates
  ├─ PasswordEncoder.matches(password, hashedPassword)
  ├─ AuthenticationManager.authenticate()
  ├─ JwtUtils.generateToken() → JWT
  ├─ RefreshTokenServiceImpl.createRefreshToken() → Refresh Token
  ├─ ELKAuditService.logAsync(AuditEventType.LOGIN_SUCCESS)
  └─ Return LoginResponseDTO
```

### 4️⃣ Backend → Database

```
SELECT * FROM gs_users WHERE email = 'user@example.com'
  ↓ (returns GsUser entity with all fields)
  ↓
SELECT * FROM gs_user_roles WHERE user_id = ?
  ↓ (returns user roles)
  ↓
INSERT INTO gs_refresh_tokens (user_id, token_value, expiry_date, device_info)
  ↓ (stores refresh token)
  ↓
POST to Elasticsearch
  Index: audit-logs
  {
    "timestamp": "2025-01-27T10:30:00Z",
    "user_id": 123,
    "action": "LOGIN_SUCCESS",
    "status": "SUCCESS",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0..."
  }
```

### 5️⃣ Backend → BFF Response

```
HTTP 200 OK
Content-Type: application/json

{
  "success": true,
  "message": "Login successful",
  "data": {
    "jwtToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
    "user": {
      "id": 123,
      "email": "user@example.com",
      "username": "john_doe",
      "roles": ["ROLE_EMPLOYEE"],
      "enabled": true,
      "accountExpiry": "2026-12-31"
    }
  },
  "timestamp": "2025-01-27T10:30:00Z"
}
```

### 6️⃣ BFF Processing

```
SigninRoute.POST()
  ├─ Receive response from backend
  ├─ Extract jwtToken from response
  ├─ encryptToken(jwtToken) using AES
  ├─ Set cookies:
  │   ├─ Set-Cookie: jwt_token=<encrypted>; HttpOnly; SameSite=Lax; Path=/
  │   └─ Set-Cookie: XSRF-TOKEN=<uuid>; SameSite=Lax; Path=/
  └─ Return response (without jwtToken, client uses cookies)
```

### 7️⃣ BFF → Frontend Response

```
HTTP 200 OK
Set-Cookie: jwt_token=<encrypted>; HttpOnly; SameSite=Lax; Path=/
Set-Cookie: XSRF-TOKEN=550e8400-e29b-41d4-a716-446655440000; SameSite=Lax; Path=/
Content-Type: application/json

{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "id": 123,
      "email": "user@example.com",
      "username": "john_doe",
      "roles": ["ROLE_EMPLOYEE"]
    },
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
  },
  "timestamp": "2025-01-27T10:30:00Z"
}
```

### 8️⃣ Frontend Storage & Usage

```
1. Frontend receives response
2. Cookies automatically stored by browser (HttpOnly = secure from JS)
3. Store refreshToken in memory or session storage
4. Store user info in React state / Context
5. Redirect to dashboard

6. Subsequent requests to BFF include cookies automatically:
   GET http://localhost:4000/api/auth/me
   Cookie: jwt_token=<encrypted>; XSRF-TOKEN=<uuid>
```

---

## Security Features Implemented

### 1. **JWT Token Management**
- Generated by Backend (Spring Security)
- Encrypted by BFF (AES encryption)
- Stored in HttpOnly cookies (protected from XSS)
- Validated on every request

### 2. **CSRF Protection**
- XSRF-TOKEN cookie (readable by JS)
- Frontend includes in X-XSRF-TOKEN header
- BFF validates token

### 3. **Account Lockout**
- Track failed login attempts
- Lock account after 5 attempts
- Unlock after cooldown period

### 4. **Account/Credential Expiry**
- `account_expiry_date` - Employee contract ends
- `credentials_expiry_date` - Password expires
- `last_password_change` - Track password age
- `must_change_password` - Force password reset on first login

### 5. **Multi-Device Session Management**
- Each device gets unique refresh token
- Can logout from specific device
- Can revoke all other sessions

### 6. **Token Reuse Detection**
- Tracks used refresh tokens
- Detects replay attacks
- Revokes token family if reuse detected

### 7. **Rate Limiting**
- `@RateLimited(maxAttempts=10, timeWindow=1, unit=HOURS)`
- Applied on signup, login, password reset endpoints

### 8. **Audit Logging (ELK)**
- All auth events logged to Elasticsearch
- Compliance tracking
- Async logging (non-blocking)

---

## Key Technologies

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Frontend** | Next.js 16, React 19, TailwindCSS | UI rendering, client-side routing |
| **BFF** | Next.js API Routes, Node.js | Gateway, token management, CSRF handling |
| **Backend** | Spring Boot 4.0.1, Java 21 | Business logic, auth, RBAC, audit |
| **Database** | PostgreSQL | Persistent storage |
| **Search** | Elasticsearch | Audit log indexing & querying |
| **Email** | Gmail SMTP | OTP, password reset notifications |

---

## Deployment Ports

- **Frontend/BFF:** `http://localhost:4000`
- **Backend API:** `http://localhost:6060/api`
- **PostgreSQL:** `localhost:5432`
- **Elasticsearch:** `http://localhost:9200`

---

## Summary

This is a **production-grade 3-tier architecture** with a dedicated **BFF layer** for:
- Secure cookie management
- Token encryption
- CSRF protection
- Request/response transformation
- Rate limiting coordination
- Centralized error handling

The separation ensures the frontend never directly accesses sensitive tokens and the backend remains isolated from frontend concerns.
