<p align="center">
  <img src="https://raw.githubusercontent.com/AsadurRahmanRishan59/Guardian-Stack/main/frontend/public/images/GS.png" alt="GuardianStack Logo" width="180" />
</p>

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

## ⚔️ Security — Things I Cared About

I used this project to properly implement security patterns I wanted to understand deeply, not just copy-paste.

### 🔨 Brute Force — Stopped Cold

At 2:47 AM, a script is hammering `/auth/public/login` — 500 attempts per minute from a single IP.

**Bucket4j rate limiting** kicks in first: 5 attempts per minute per IP, then `429 Too Many Requests`. The script crawls to a halt. For any accounts the script reaches, **account lockout** activates after 5 consecutive failures — `account_locked = TRUE`, `locked_until = NOW() + 30 minutes`. Every failed attempt is written asynchronously to `gs_auth_audit_log` and streamed to ELK. Within 2 minutes the admin sees a wall of `LOGIN_FAILURE` events in Kibana, traces the IP, and blocks the subnet. Accounts compromised: **zero**.

### 🕵️ The Rogue Admin — Caught by Envers

Admin Karim decides to lower a tariff rate for his own benefit — drops `own_dp_basic` from ৳850 to ৳200. He thinks no one will notice.

The `gs_motor_tariff` table is annotated with `@Audited`. The moment his transaction commits, Hibernate Envers writes a revision to `gs_motor_tariff_aud` — change type UPDATE, old value, new value, and the author captured from the Spring Security context at commit time. You cannot fake this.

At month-end, the Master Admin reviews the audit timeline. She sees the diff. The revision is attributed to Karim. His access is revoked — that revocation is itself written to `gs_user_roles_aud`. The audit tables are append-only. Nothing can be hidden retroactively.

### 🔐 Stolen Device — Revoke in 45 Seconds

Customer Sajida's phone is stolen. She borrows a friend's phone, logs in, goes to **Account → Active Sessions**, sees her stolen phone still active (Android/Chrome, last seen 8 minutes ago), and clicks **"Log out all other devices"**. Every refresh token for her account is invalidated in `gs_refresh_tokens` except the current session. The stolen phone's JWT can't be refreshed. The attack window is closed in under a minute.

### 🛡️ CSRF — A Lesson I Had to Learn by Building It

This one I thought I understood. I didn't — not until I actually built it.

The common assumption: *"I'm using JWT, so I don't need to worry about CSRF."*

That's wrong — and it depends entirely on **where you store the token**.

Browsers automatically send cookies with every request to a matching domain. They don't care who triggered the request — your own app or a malicious third-party page. If your JWT lives in a cookie, a CSRF attack can absolutely use it.

**How GuardianStack's architecture solves this at the design level:**

```
Browser → Next.js API Routes (BFF) → Spring Boot
```

The browser never talks to Spring Boot directly. Next.js Route Handlers sit in the middle as a **Backend For Frontend (BFF)**:

- They receive browser requests (the risky leg — cookies are sent automatically here)
- They validate auth and CSRF at the BFF layer
- They forward requests to Spring Boot **with server-added `Authorization` headers**

That last step is the key. A browser cannot forge server-to-server headers. An attacker's phishing page cannot make Next.js add an `Authorization: Bearer <token>` header on their behalf — that happens server-side, in code the attacker has no access to.

Spring Boot therefore **never needs its own CSRF protection** — it only accepts requests from Next.js with those manually-attached headers. The CSRF problem is fully resolved one layer up.

Three things I confirmed by building this:
- **JWT does not automatically mean no CSRF** — token storage location is what matters
- **HTTPS does not stop CSRF** — it encrypts the channel, not the request origin
- **SameSite cookies help, but are not a complete solution**

> I built a minimal POC demonstrating the vulnerable case vs. the fixed case:  
> [CSRF POC — vulnerable vs. fixed](https://lnkd.in/gps7g535)

### 🚨 Late Night Hack — Traced on ELK

ELK detects the same employee account making API calls from Bangladesh and the Netherlands within 4 minutes. Physically impossible. The Watcher alert fires. The admin gets a push notification, opens Kibana, traces the full session from the initial phishing click to the fraudulent API calls. Account locked. Full lifecycle of the attack reconstructed from logs. Fraudulent policy approvals: **zero**.

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