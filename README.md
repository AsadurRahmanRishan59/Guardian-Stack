# <img src="https://raw.githubusercontent.com/AsadurRahmanRishan59/Guardian-Stack/main/frontend/public/images/GS.png" width="32" style="vertical-align:middle" /> GuardianStack

> A personal project — building a full-stack motor insurance platform from scratch, the way I think it should actually work in Bangladesh.

<p align="center">
  <img src="https://img.shields.io/badge/Status-In%20Development-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Backend-Spring%20Boot%204-6DB33F?style=for-the-badge&logo=spring" />
  <img src="https://img.shields.io/badge/Frontend-Next.js%2016-black?style=for-the-badge&logo=next.js" />
  <img src="https://img.shields.io/badge/Database-PostgreSQL-316192?style=for-the-badge&logo=postgresql" />
  <img src="https://img.shields.io/badge/Audit-Hibernate%20Envers-59666C?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Observability-ELK%20Stack-005571?style=for-the-badge&logo=elastic" />
</p>

---

## 🤔 Why This Exists

I work as a software engineer at a non-life insurance company in Bangladesh. I see how the industry operates up close — and how much of it is still paper-based, agent-driven, and offline. A customer who wants to insure their car today still has to call someone, visit an office, or trust a third-party broker.

GuardianStack is my personal attempt to build what that experience *should* look like — designed from scratch, on my own time, without the constraints of legacy systems or office politics. The architecture decisions here (ELK, Envers, async audit pipeline, stateless JWT) are ones I believe in, not ones inherited from a codebase that predates me.

It's a pet project. Not a startup, not a product launch. Just me building something properly, end to end, once.

---

## 🌍 What It Does (When Complete)

GuardianStack is two things in one:

**For customers** — a public web app where you can get a motor insurance quote in seconds, sign up, complete your policy form, upload your Blue Book, and pay online. Your dashboard keeps all your policies in one place. Your physical stamped certificate gets couriered to you.

**For the insurance company's staff** — an internal operations panel where employees review submitted policies, verify documents, adjust premiums if needed, and approve applications. Admins manage users and access. A Master Admin controls the tariff tables and has visibility into every audit log in the system.

The two sides are the same app, scoped by role.

---

## 🧭 A User's Full Journey

**Farhan** has been putting off insuring his 2019 Toyota Allion for months. Tonight he finally does it.

He opens GuardianStack and clicks **Motor Insurance → Get a Quote**. He enters: Private Vehicle, Passenger Car, 1500cc, insured value ৳18,00,000. The system looks up the IDRA-regulated tariff table and in under a second shows him a full premium breakdown — Own Damage, Act Liability, Fire, Theft, Cyclone, Earthquake. The total: **৳24,850/year**. Real numbers, not estimates.

He clicks **Buy Now** and signs up — name, email, password. An OTP hits his inbox. He verifies. He's in.

He lands on the **Motor Policy Form**. His earlier quote is already pre-filled. He completes the rest: NID number, date of birth, address, registration number, chassis, engine number. He selects **No Claim Bonus — 20%** since he had no claims last year, uploads his Blue Book and previous policy as proof, and submits.

His dashboard shows: **Policy #MT-2025-004817 — Pending Verification**.

---

**Rafiq**, an employee, gets notified. He opens the policy, cross-checks the Blue Book against the submitted details, confirms the NCB is legitimate, and approves. Final premium: **৳19,880**.

Farhan gets an email. He logs back in, reads the terms, and pays via bKash. Instantly he gets a PDF policy token in his dashboard. A physical government-stamped certificate is dispatched for same-day courier delivery in Dhaka.

---

## ⚔️ Security Stories — When GuardianStack Gets Tested

I used this project to properly implement security patterns I wanted to understand deeply, not just copy-paste. Here's what happens when each one gets tested.

---

### 🔨 Story 1: The Brute Force Attack

It's 2:47 AM. Someone in Chittagong is running a credential-stuffing script against `/auth/public/login`. They've acquired a leaked email list and are hammering the endpoint with 500 password attempts per minute.

GuardianStack's defenses activate in layers:

**Layer 1 — Rate Limiting (Bucket4j)**  
The endpoint is decorated with `@RateLimited`. Each IP gets a token bucket — 5 attempts per minute. After the 5th failed attempt, the attacker receives `429 Too Many Requests`. Their script slows to a crawl. The attack's effectiveness drops by 99%.

**Layer 2 — Account Lockout**  
For the few accounts the script manages to reach, lockout activates after 5 consecutive failures — `account_locked = TRUE` and `locked_until = NOW() + 30 minutes` is written to `gs_users`. Subsequent attempts return `423 Account Locked` immediately, without even checking the password — a deliberate early exit to prevent timing attacks.

**Layer 3 — Audit Logging**  
Every failed attempt is written asynchronously to `gs_auth_audit_log` with: timestamp, IP address, user-agent, device fingerprint, attempted email, and event type `LOGIN_FAILURE`. The ELK pipeline ingests these in real time.

**Layer 4 — The Alert**  
At 2:49 AM, the ELK Watcher fires: *"Login failure rate exceeded 200/min from a single IP subnet."* The on-call admin, **Nazia**, gets a push notification. She opens **Audit → Login Log** and sees a wall of red `LOGIN_FAILURE` events from `103.x.x.x`. She traces the full lifecycle in Kibana in under 3 minutes. The subnet is blocked at the infrastructure level. Total accounts compromised: **zero**.

---

### 🕵️ Story 2: The Rogue Admin Gets Caught

**Karim** is a Normal Admin. He has a grudge. He decides to modify a tariff rate to favor a specific vehicle class — lowering the premium for Private Vehicles under 1300cc. He changes `own_dp_basic` from ৳850 to ৳200 on that tariff record.

He thinks no one will notice. He's wrong.

The `gs_motor_tariff` table is annotated with `@Audited` via Hibernate Envers. The moment Karim's API call commits the transaction, Envers writes a new row to `gs_motor_tariff_aud`:

```
tariff_key: 7  |  rev: 1842  |  revtype: 1 (UPDATE)
own_dp_basic: 200.00  ← changed from 850.00
created_by: karim@guardianstack.com
timestamp: 2025-03-10 11:34:22
```

The `revinfo` table records the revision author via `CustomRevisionListener` — it captures the authenticated username from the Spring Security context at commit time. You cannot fake this. It happens inside the transaction.

At month-end, the Master Admin opens **Master Data → Tariffs → Motor → Audit Timeline**. She sees the diff — `own_dp_basic` dropped from 850 to 200 on March 10th. The revision is attributed to Karim. She clicks **Inspector** and sees the full before/after state of every field in that revision.

Karim's access is revoked. His role change is itself written to `gs_user_roles_aud`. The immutable record stands. Nothing was deleted. Nothing was hidden. The audit tables are read-only by design — not even the Master Admin can modify them.

---

### 🔐 Story 3: The Stolen Device

**Sajida** is a regular customer. Her phone is stolen at a shopping mall. The thief can see she's logged into GuardianStack — her session token is live.

Sajida borrows a friend's phone and logs in. She navigates to **Account → Active Sessions**. She can see every active session: her stolen phone (last seen 8 minutes ago, device fingerprint: Android/Chrome), her laptop at home, and this current session.

She clicks **"Log out all other devices"**. The system invalidates all refresh tokens for her account in `gs_refresh_tokens` except the current one. The stolen phone's session is dead. Even if the thief tries to silently refresh the JWT, the refresh token returns `401 Token Revoked`. The entire session revocation took her 45 seconds.

---

### 🛡️ Story 4: The CSRF Attempt — And What I Actually Learned

A phishing site tricks a GuardianStack employee into clicking a disguised link. The malicious page fires a cross-origin POST to `https://app.guardianstack.com/admin/user/123/role` attempting to elevate a user's privileges.

This is where I had to unlearn something. The common assumption: *"I'm using JWT, so CSRF isn't my problem."* That's wrong — and it depends entirely on **where you store the token**. Browsers automatically send cookies with every request to a matching domain. If your JWT is in a cookie, a CSRF attack can absolutely use it.

**How GuardianStack solves this at the architecture level:**

```
Browser → Next.js Route Handlers (BFF) → Spring Boot
```

The browser never talks to Spring Boot directly. Next.js sits in the middle as a **Backend For Frontend**:

- It receives browser requests (the risky leg — cookies are sent automatically here)
- It validates auth and CSRF at the BFF layer
- It forwards requests to Spring Boot **with server-added `Authorization` headers**

A browser cannot forge server-to-server headers. An attacker's phishing page cannot make Next.js add an `Authorization: Bearer <token>` on their behalf — that happens server-side, in code the attacker has no access to. Spring Boot therefore **never needs its own CSRF protection** — the problem is resolved one layer up.

Three things I confirmed by building this:
- **JWT does not automatically mean no CSRF** — token storage location is what matters
- **HTTPS does not stop CSRF** — it encrypts the channel, not the request origin
- **SameSite cookies help, but are not a complete solution**

> I built a minimal POC showing the vulnerable case vs. the fixed case: [CSRF POC](https://lnkd.in/gps7g535)

---

### 🚨 Story 5: The Late Night Hack Alert

It's 11:58 PM on a Wednesday. ELK detects an anomaly: an authenticated session belonging to employee **Hasan** is making API calls from Bangladesh and the Netherlands simultaneously — within a 4-minute window. Physically impossible.

The Watcher alert fires: *"Impossible travel detected — hasan@guardianstack.com. BD → NL in 4 minutes."*

The on-call admin gets a critical alert on her phone. She investigates:

1. **Audit → Login Log** — Hasan's legitimate Dhaka login at 11:42 PM, then a login from a Dutch IP at 11:46 PM using the same refresh token.
2. **ELK Kibana** — she pulls the full session trace. The Dutch IP is hitting the policy approval endpoints. Someone is trying to approve fraudulent policies at midnight.
3. **Action** — she navigates to **User Management → Hasan → Active Sessions**, force-revokes all tokens. Account locked pending investigation. Incident noted in the audit log.
4. **Morning debrief** — the full attack lifecycle is reconstructed from ELK: the original vector was a phishing email Hasan clicked at 11:39 PM, exposing his refresh token. Everything from the initial phish to the admin response is traceable in the logs. Fraudulent policies approved: **zero** (the approval endpoint requires document verification state, which the attacker hadn't bypassed).

---

## 🏗️ Architecture

I work as a software engineer at a non-life insurance company in Bangladesh. This project is my attempt to build the platform the right way — on my own terms, with the stack and patterns I actually believe in — separate from the day job constraints.

```
┌──────────────────────────────────────────────────────────────┐
│                      Browser / Mobile                         │
│                                                               │
│   Next.js 16 (App Router)  ·  React 19  ·  TypeScript        │
│   shadcn/ui + Radix UI  ·  Tailwind CSS 4  ·  Motion         │
│   TanStack Query v5  ·  TanStack Table v8                     │
│   React Hook Form  ·  Zod v4  ·  Sonner (toasts)             │
└─────────────────────────────┬────────────────────────────────┘
                              │  REST (JSON)
                              │  Next.js Route Handlers as proxy
                              │  (backend never directly exposed)
┌─────────────────────────────▼────────────────────────────────┐
│                   Spring Boot 4 REST API                      │
│                        Java 21                                │
│                                                               │
│   Spring Security  ·  jjwt 0.13  ·  Passay (password policy) │
│   Bucket4j (rate limiting)  ·  JavaMailSender                 │
│   Async Audit Pipeline  ·  MDC + Correlation IDs             │
│   Logstash Logback Encoder                                    │
└──────────────┬───────────────────────────┬───────────────────┘
               │                           │
┌──────────────▼──────────┐   ┌────────────▼────────────────────┐
│       PostgreSQL         │   │          ELK Stack              │
│                          │   │                                 │
│  gs_users                │   │  Elasticsearch                  │
│  gs_user_roles           │   │  Logstash (log ingestion)       │
│  gs_refresh_tokens       │   │  Kibana dashboards              │
│  gs_verification_tokens  │   │  Kibana Watcher (alerts)        │
│  gs_auth_audit_log       │   │                                 │
│  gs_motor_tariff         │   │  → Brute force detection        │
│  gs_policies (planned)   │   │  → Impossible travel alerts     │
│  gs_*_aud (Envers)       │   │  → After-hours activity flags   │
│  revinfo                 │   │  → Full attack lifecycle trace  │
└──────────────────────────┘   └─────────────────────────────────┘
```

### A note on the proxy layer

The frontend never calls the Spring Boot API directly. All requests go through Next.js Route Handlers, which forward them server-side. This keeps the backend URL off the client entirely — no CORS headers needed on the backend, no API base URL in the browser.

---

## 📦 Stack

| Layer | Tech | Version |
|---|---|---|
| Frontend Framework | Next.js | 16.1.1 |
| UI Runtime | React | 19.2.3 |
| Language | TypeScript | ^5 |
| Styling | Tailwind CSS | v4 |
| Component Library | shadcn/ui + Radix UI | latest |
| Animations | Motion (Framer) | ^12 |
| Server State | TanStack Query | v5 |
| Tables | TanStack Table | v8 |
| Forms | React Hook Form + Zod | Zod v4 |
| Notifications | Sonner | ^2 |
| Backend Framework | Spring Boot | 4.0.1 |
| Language | Java | 21 |
| Security | Spring Security + jjwt | jjwt 0.13 |
| Password Policy | Passay | 1.6.6 |
| Rate Limiting | Bucket4j | — |
| ORM | Spring Data JPA + Hibernate Envers | — |
| Database | PostgreSQL | 15+ |
| Search / Audit | Spring Data Elasticsearch | — |
| Log Shipping | Logstash Logback Encoder | 8.0 |
| Email | Spring Mail (JavaMailSender) | — |

---

## 👥 Roles

| Role | Description |
|---|---|
| `ROLE_MASTER_ADMIN` | Full access. Manages tariffs, all users, reads all audit logs. Cannot modify audit records. |
| `ROLE_ADMIN` | Manages users/employees. Unlocks policies for editing. Views audit logs. |
| `ROLE_EMPLOYEE` | Reviews policies, verifies documents, adjusts premiums, approves applications. |
| `ROLE_USER` | Customer. Quotes, buys, pays, manages their own policies. |

---

## 📋 What's Built / What's Left

See **[CHECKLIST.md](./CHECKLIST.md)** — a full breakdown of every feature, organized by domain, with done/in-progress/todo status.

The auth and IAM layer is the most complete part. Policy purchase, payment, and document delivery are next.

---

## 🚀 Running Locally

### Backend
```bash
cd backend
# Fill in application.yml with your DB credentials
./mvnw spring-boot:run
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

---

## 📝 Notes

- Some of the architecture choices here (ELK, Hibernate Envers, async audit pipeline, Spring Boot 4 + Java 21) are more than a side project strictly needs — that's intentional. I work with insurance systems daily and I wanted to implement these patterns the right way, at least once, where I fully control the decisions.
- The insurance tariff structure and premium calculation logic follow IDRA (Insurance Development and Regulatory Authority) of Bangladesh regulations.
- No real payments or real policies are issued. This is not a licensed insurance product.
- Spring Boot 4 + Java 21 is bleeding edge as of this project's start. Chosen deliberately.

---

<p align="center">Solo project · Built in Bangladesh 🇧🇩</p>