# ✅ GuardianStack — Build Checklist

> Track what's done, what's in progress, and what's still to build.  
> Updated as the project evolves. Each section maps to a domain of the system.

---

## 🔐 Authentication & Identity (IAM)

### Done ✅
- [x] User signup with name, email, password
- [x] BCrypt password hashing (cost factor 12)
- [x] Email OTP verification on signup (account disabled until verified)
- [x] OTP expiry and verification attempt counter (brute-force resistant)
- [x] OTP resend with cooldown logic
- [x] JWT access token issuance on login
- [x] Refresh token with rotation — old token invalidated on each use
- [x] Refresh token reuse detection — flags replay attacks
- [x] Forgot password via OTP email
- [x] Password reset with OTP verification
- [x] Account lockout after 5 consecutive failed logins
- [x] Timed unlock — account auto-unlocks after 30 minutes
- [x] Manual unlock endpoint (Admin/Master Admin)
- [x] Rate limiting on all sensitive auth endpoints (`@RateLimited` via Bucket4j)
- [x] Device fingerprinting on login (stored with session)
- [x] Active session listing per user
- [x] Revoke individual session (logout single device)
- [x] Revoke all sessions except current ("stolen device" flow)
- [x] Account/credential expiry fields (for employees — contract-based access)
- [x] `must_change_password` flag (force password change on first login for admin-created accounts)
- [x] Role-based access control: `MASTER_ADMIN`, `ADMIN`, `EMPLOYEE`, `USER`
- [x] Method-level security (`@PreAuthorize`, `@Secured`)
- [x] Email policy validation (format, domain rules)
- [x] Password policy validation (length, complexity)
- [x] Global exception handler with structured error responses
- [x] `AuthShell.tsx` — shared layout for all auth pages
- [x] Login page (email + password)
- [x] Signup page
- [x] OTP verification page
- [x] Forgot password page
- [x] Reset password page

### In Progress 🔄
- [ ] Google OAuth2 signup/login (`sign_up_method = GOOGLE` field exists, flow not built)
- [ ] "Remember this device" — trusted device registry to skip 2FA

### To Do 📋
- [ ] Two-factor authentication (TOTP via authenticator app) for admin roles
- [ ] Session expiry warning — frontend countdown before JWT expires
- [ ] Login history page for customers (view their own past logins)

---

## 👤 Customer Profile & Account

### Done ✅
- [x] User entity with full audit fields (`created_at`, `updated_at`, `created_by`, `updated_by`)
- [x] Hibernate Envers on `gs_users` and `gs_user_roles` — full revision history
- [x] `gs_users_aud` and `gs_user_roles_aud` audit tables with indexes
- [x] `revinfo` table with custom `CustomRevisionEntity` (captures who made the change)

### To Do 📋
- [ ] Customer profile page — view and edit personal details (name, NID, DOB, phone)
- [ ] Multiple address management — home, office, delivery address
- [ ] Address CRUD with soft delete
- [ ] Profile change audit (all edits tracked in audit tables)
- [ ] Profile picture upload
- [ ] Phone number with OTP verification
- [ ] NID/passport number storage and masking in UI

---

## 🚗 Motor Insurance — Quotation

### Done ✅
- [x] `gs_motor_tariff` table with all IDRA regulatory fields
- [x] Tariff types: Private Vehicle, Motor Cycle, Commercial Vehicle
- [x] Premium components: Own Damage Basic, Full Insurance Value %, Act Liability, Fire, Theft, Cyclone, Earthquake
- [x] `MotorTariff` entity with validation constraints
- [x] Hibernate Envers on `gs_motor_tariff` — tariff change history
- [x] `gs_motor_tariff_aud` table
- [x] Master Admin tariff CRUD API
- [x] Master Admin tariff list with filtering, search, pagination
- [x] `MotorTariffContainer`, `MotorTariffList`, `MotorTariffForm`, `MotorTariffViewModal`
- [x] `MotorTariffFilterForm` with search criteria
- [x] Tariff hierarchy levels (`MotorHierarchyLevel`)

### To Do 📋
- [ ] **Public quotation form** — no login required
  - [ ] Vehicle type / group / CC / insured value inputs
  - [ ] Real-time premium calculation from tariff table
  - [ ] Premium breakdown display (itemised by component)
  - [ ] Quote persistence in session/localStorage — carries over post-login
- [ ] Quote-to-policy handoff — pre-fill policy form with quotation data
- [ ] Quote expiry (quotes valid for 7 days)
- [ ] Quote PDF download (summary for customer to consider)

---

## 📋 Motor Insurance — Policy Purchase

### To Do 📋
- [ ] **Policy application form** (authenticated)
  - [ ] Pre-fill from saved quotation
  - [ ] Personal details section: full name, NID/passport, DOB, phone, occupation
  - [ ] Vehicle details section: registration number, chassis, engine number, colour, year, make, model
  - [ ] Address section: insured address, correspondence address, delivery address
  - [ ] No Claim Bonus section — NCB % selection with eligibility rules
  - [ ] Coverage period selection (1 year standard, custom range)
  - [ ] Approximate premium display (live, updates on field change)
- [ ] **Document upload**
  - [ ] Blue Book (vehicle registration certificate) upload
  - [ ] Previous year policy certificate (for NCB)
  - [ ] NID/passport scan upload
  - [ ] Multi-file upload with progress indicator
  - [ ] File type and size validation (PDF/JPG/PNG, max 5MB each)
  - [ ] Uploaded document viewer in-app
- [ ] Policy submission with status: `PENDING_VERIFICATION`
- [ ] Policy draft saving (auto-save every 30s, resume later)
- [ ] Customer policy dashboard — list of all policies with status badges
- [ ] Policy detail view — full policy info, documents, payment history

---

## 🧑‍💼 Employee Workflow

### To Do 📋
- [ ] Employee work queue — list of policies in `PENDING_VERIFICATION`
- [ ] Policy review screen
  - [ ] Side-by-side: submitted details vs uploaded documents
  - [ ] Document viewer (inline PDF/image rendering)
  - [ ] Field-level edit capability on verified premium components
  - [ ] NCB verification — approve or reject with reason
  - [ ] Premium recalculation after adjustments
  - [ ] Internal notes field (not visible to customer)
- [ ] Policy approval flow → status: `AWAITING_PAYMENT`
- [ ] Policy rejection flow with reason → customer notified
- [ ] Request more documents from customer
- [ ] Policy lock/unlock mechanism (Admin grants unlock access)
- [ ] Employee notification system
  - [ ] In-app notification on new policy submission
  - [ ] Email notification on new policy submission
  - [ ] Notification badge in sidebar

---

## 💳 Payment

### To Do 📋
- [ ] Payment initiation from policy detail page
- [ ] Online payment gateway integration (bKash / SSLCommerz / Nagad)
- [ ] Payment confirmation webhook handling
- [ ] Payment status: `PAYMENT_PENDING` → `PAID`
- [ ] Payment receipt generation (on-screen + downloadable PDF)
- [ ] Policy token PDF generation — downloadable proof of coverage
- [ ] Policy status after payment: `ACTIVE`
- [ ] Failed payment retry flow
- [ ] Refund workflow (partial/full, admin-initiated)
- [ ] Payment history per policy

---

## 📄 Document Delivery

### To Do 📋
- [ ] Physical document dispatch queue (internal admin view)
- [ ] Delivery address confirmation screen for customer
- [ ] Dhaka same-day delivery flag logic
- [ ] Courier integration or manual dispatch tracking
- [ ] Delivery status tracking for customer
- [ ] Stamped policy certificate upload by employee (proof of dispatch)

---

## 📧 Email Notifications

### Done ✅
- [x] `MailService` / `MailServiceImpl` wired
- [x] OTP email on signup
- [x] OTP email on forgot password

### To Do 📋
- [ ] Policy submission confirmation email (to customer)
- [ ] Policy verified + payment request email (to customer)
- [ ] Policy approved / payment confirmed email (to customer)
- [ ] Policy rejection email with reason (to customer)
- [ ] New policy submission alert email (to employee)
- [ ] Payment receipt email with PDF attachment
- [ ] Policy certificate email with PDF attachment
- [ ] Renewal reminder email (30 days before policy expiry)
- [ ] Email templates (HTML, branded GuardianStack design)

---

## 👑 Master Admin Panel

### Done ✅
- [x] Master Admin user CRUD (create, view, update, enable/disable)
- [x] `MasterAdminUserController`, service, mapper, specifications
- [x] User search with filters (role, status, date range, keyword)
- [x] Paginated user list with column visibility
- [x] Role assignment / removal
- [x] User audit timeline — diff view per revision (Envers-backed)
- [x] `DiffTable`, `TimeLineRail`, `Inspector`, `StatsStrip` UI components
- [x] Motor tariff management (CRUD, filter, view)
- [x] Tariff audit history (Envers)

### To Do 📋
- [ ] Dashboard home — key metrics (total policies, pending verifications, active policies, revenue)
- [ ] All insurance product tariff management (Health, Overseas, Home, Life, SME)
- [ ] Policy override — Master Admin can modify any policy at any stage
- [ ] Bulk user operations (bulk enable/disable, bulk role assign)
- [ ] System configuration panel (lockout threshold, OTP expiry duration, etc.)
- [ ] Announcement/notification broadcast to all users

---

## 🔧 Admin Panel

### Done ✅
- [x] `RoleController` / `RoleService` — role listing
- [x] Admin-accessible user management routes (scoped)

### To Do 📋
- [ ] Admin dashboard — pending policy count, employee queue depth
- [ ] Policy unlock for employee editing (upon customer request)
- [ ] Employee management — create, disable, reset password
- [ ] Admin audit view (scoped — only their team's actions)
- [ ] Customer support tools — view any customer's policy, add internal note

---

## 📊 Audit & Observability

### Done ✅
- [x] `gs_auth_audit_log` — all auth events (login, logout, OTP, lockout, token events)
- [x] `AuthAuditLog` entity + `AuthAuditLogRepository`
- [x] `AsyncAuditProcessor` + `AuditDbWriter` — async write pipeline
- [x] `AuditContext` + `AuditContextFilter` — request metadata propagation
- [x] MDC with correlation IDs — traceable across async threads via `MdcTaskDecorator`
- [x] `ELKAuditService` — structured JSON audit events to ELK pipeline
- [x] `AuditEventType` enum — typed event catalogue
- [x] Logback structured logging config (`LOGBACK-SPRING.XML`)
- [x] Hibernate Envers on users, user roles, motor tariffs
- [x] Custom `RevisionEntity` with author capture
- [x] `UserAuditController` — audit log API endpoints
- [x] `MasterAdminUserAuditController` — master admin audit view
- [x] `AuditDiffMapper`, `AuditDiffDTO`, `AuditTimelineItemDTO`
- [x] Frontend audit components: `DiffTable`, `TimeLineRail`, `Inspector`, `FilterBar`, `StatsStrip`, `TopBar`
- [x] Login Log page (auth audit log view)
- [x] User Log page (user change audit view)

### To Do 📋
- [ ] Policy audit log — every status change, field change, approval event
- [ ] Payment audit log
- [ ] ELK Kibana dashboard setup (pre-built index patterns + dashboards)
- [ ] Watcher alert rules in ELK:
  - [ ] Brute force detection (N failures/min from same IP)
  - [ ] Impossible travel detection (same account, two countries, short window)
  - [ ] After-hours admin activity alert
  - [ ] Mass policy approval anomaly
- [ ] Admin in-app alert notification (real-time, WebSocket or SSE)
- [ ] Alert history page in admin dashboard
- [ ] Audit export to CSV/Excel (for compliance reports)

---

## 🌐 Frontend — General

### Done ✅
- [x] Next.js 15 App Router setup
- [x] Global layout with `Providers`, `QueryProvider`, `ThemeProvider`
- [x] Dark/light mode toggle
- [x] `AuthGuard` — redirects unauthenticated users
- [x] `RoleGuard` — renders content based on user role
- [x] `ProtectedRoute` component
- [x] Dynamic sidebar navigation (`app-sidebar`, `nav-main`) — role-filtered
- [x] `DataTable` — reusable server-paginated table with filters
- [x] `useDataTable` hook
- [x] `TablePagination`, `TableSearch`, `TableControls`, `FilterToggle`, `ColumnVisibility`
- [x] `ComboboxSelect` component with usage guide
- [x] `ConfirmDialog` — reusable confirmation modal
- [x] `generateColumns` — dynamic column builder
- [x] API client with interceptors (`api_client.ts`)
- [x] Error handling utilities (`error-handling.ts`)
- [x] Crypto utilities (`crypto.ts`)
- [x] Device fingerprinting (`fingerprint.ts`)
- [x] Role-check utilities (`role-check.ts`)
- [x] `useDebounce` hook

### To Do 📋
- [ ] Landing page — public marketing page with product showcase
- [ ] Product cards (Motor, Health, Overseas, Home, Life, SME)
- [ ] Responsive mobile layout (all pages)
- [ ] Toast notification system (success/error/info)
- [ ] Loading skeletons for all data-fetching views
- [ ] Empty state components
- [ ] 404 and error boundary pages
- [ ] Accessibility audit (ARIA labels, keyboard navigation)
- [ ] SEO metadata (Open Graph, structured data)

---

## 🛡️ Security Hardening

### Done ✅
- [x] Stateless JWT — no session cookies (CSRF surface = zero)
- [x] CORS configuration
- [x] BCrypt with high cost factor
- [x] Rate limiting on auth endpoints
- [x] Account lockout with timed auto-unlock
- [x] Refresh token reuse detection
- [x] Device fingerprinting
- [x] Input validation (Bean Validation + Zod on frontend)
- [x] Structured error responses (no stack traces to client)

### To Do 📋
- [ ] HTTPS enforcement in production (HSTS header)
- [ ] API gateway / WAF in front of backend
- [ ] IP allowlist for admin panel (optional)
- [ ] Secrets management (AWS Secrets Manager / HashiCorp Vault)
- [ ] Security headers (`X-Frame-Options`, `Content-Security-Policy`, etc.)
- [ ] Penetration test before go-live
- [ ] Dependency vulnerability scan (OWASP Dependency-Check in CI)

---

## ⚙️ Infrastructure & DevOps

### To Do 📋
- [ ] Dockerfile for backend
- [ ] Dockerfile for frontend
- [ ] `docker-compose.yml` (backend + frontend + postgres + ELK)
- [ ] GitHub Actions CI pipeline
  - [ ] Build and test on push
  - [ ] Lint frontend
  - [ ] OWASP dependency check
- [ ] Environment variable management (`.env.example` files)
- [ ] Database migration tool (Flyway or Liquibase)
- [ ] Production deployment guide
- [ ] Staging environment setup

---

## 📱 Future / Stretch Goals

- [ ] Native mobile app (React Native)
- [ ] WhatsApp notification integration
- [ ] Policy renewal reminders (email + in-app)
- [ ] Agent portal (for insurance brokers who submit on behalf of customers)
- [ ] Health insurance quotation and purchase flow
- [ ] Overseas Medical insurance flow
- [ ] Claims submission portal
- [ ] Claims tracking and status updates
- [ ] Multi-language support (Bengali / English)

---

<p align="center">
  <b>Legend:</b> ✅ Done &nbsp;|&nbsp; 🔄 In Progress &nbsp;|&nbsp; 📋 To Do
</p>