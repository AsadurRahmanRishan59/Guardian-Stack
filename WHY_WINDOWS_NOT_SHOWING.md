# Device Name Not Showing: Root Cause & Solution

## Root Cause

When you log in from Windows, the device name shows as **"Unknown Device"** instead of **"Windows PC"** because:

### The Problem Chain

1. **Browser sends User-Agent header** ✅
   ```
   User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...
   ```

2. **Next.js (BFF) receives it but DOESN'T forward it** ❌
   ```typescript
   // app/api/auth/signin/route.ts (WRONG)
   const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/signin`, {
     method: 'POST',
     headers: {
       'Content-Type': 'application/json',  // ❌ User-Agent is missing!
     },
   });
   ```

3. **Spring Boot receives request WITHOUT User-Agent** ❌
   ```java
   // RefreshTokenServiceImpl.java line 390
   private String parseDeviceName(String userAgent) {
       if (userAgent == null || userAgent.isEmpty()) return "Unknown Device"; // ← Here!
       
       if (userAgent.contains("Windows")) return "Windows PC";
       // ...
   }
   ```

4. **Database stores "Unknown Device"** ❌
   ```
   device_name = "Unknown Device"
   ```

---

## Solution: Forward User-Agent Header

### The Fix

Extract User-Agent from incoming request and forward it to backend:

```typescript
// BEFORE (WRONG):
const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/signin`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
});

// AFTER (CORRECT):
const userAgent = request.headers.get('user-agent') || 'unknown';
const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/signin`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'User-Agent': userAgent,  // ✅ Forward it!
  },
});
```

---

## Files That Need to Be Fixed

All auth route files need this fix:

| File | Status |
|------|--------|
| [app/api/auth/signin/route.ts](../../frontend/app/api/auth/signin/route.ts) | ❌ Missing User-Agent |
| [app/api/auth/signup/route.ts](../../frontend/app/api/auth/signup/route.ts) | ❌ Missing User-Agent |
| [app/api/auth/verify-otp/route.ts](../../frontend/app/api/auth/verify-otp/route.ts) | ❌ Missing User-Agent |
| [app/api/auth/resend-otp/route.ts](../../frontend/app/api/auth/resend-otp/route.ts) | ❌ Missing User-Agent |
| [app/api/auth/reset-password/route.ts](../../frontend/app/api/auth/reset-password/route.ts) | ❌ Missing User-Agent |
| [app/api/auth/forgot-password/route.ts](../../frontend/app/api/auth/forgot-password/route.ts) | ❌ Missing User-Agent |
| [app/api/auth/me/route.ts](../../frontend/app/api/auth/me/route.ts) | ❌ Missing User-Agent |

Also **admin routes**:
| [app/api/admin/user/route.ts](../../frontend/app/api/admin/user/route.ts) | ✅ Uses `getAuthHeaders()` |
| [app/api/admin/user/[userId]/route.ts](../../frontend/app/api/admin/user/[userId]/route.ts) | ✅ Uses `getAuthHeaders()` |

---

## Device Name Parsing Logic (Backend)

This is how backend determines device name from User-Agent:

```java
// RefreshTokenServiceImpl.java line 391-400
private String parseDeviceName(String userAgent) {
    if (userAgent == null || userAgent.isEmpty()) return "Unknown Device";
    
    if (userAgent.contains("Windows")) return "Windows PC";
    else if (userAgent.contains("Mac")) return "Mac";
    else if (userAgent.contains("iPhone")) return "iPhone";
    else if (userAgent.contains("iPad")) return "iPad";
    else if (userAgent.contains("Android")) return "Android Device";
    else if (userAgent.contains("Linux")) return "Linux PC";
    else if (userAgent.contains("Postman")) return "Postman";
    
    return "Unknown Device";
}
```

**Supported Device Names:**
- Windows PC (Windows NT)
- Mac (Macintosh)
- iPhone
- iPad
- Android Device
- Linux PC
- Postman (for API testing)
- Unknown Device (default)

---

## Example User-Agent Strings

### Windows
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
```
→ Parsed as: **Windows PC** ✅

### macOS
```
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
```
→ Parsed as: **Mac** ✅

### iPhone
```
Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1
```
→ Parsed as: **iPhone** ✅

### Android
```
Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36
```
→ Parsed as: **Android Device** ✅

---

## How to Fix

### Option 1: Create Header Utility Function

**File:** Create [lib/api/headers.ts](../../frontend/lib/api/headers.ts)

```typescript
import { NextRequest } from 'next/server';

export function getUserAgent(request: NextRequest): string {
    return request.headers.get('user-agent') || 'unknown';
}

export function getRequestHeaders(request: NextRequest): HeadersInit {
    return {
        'Content-Type': 'application/json',
        'User-Agent': getUserAgent(request),
    };
}
```

Then use in all routes:

```typescript
import { getRequestHeaders } from '@/lib/api/headers';

const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/signin`, {
    method: 'POST',
    headers: getRequestHeaders(request),
    body: JSON.stringify(body),
});
```

### Option 2: Inline Fix (Simpler)

Just add one line to each route:

```typescript
const userAgent = request.headers.get('user-agent') || 'unknown';
const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/signin`, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'User-Agent': userAgent,  // ← Add this line
    },
});
```

---

## Complete Fix for All Files

### 1. [app/api/auth/signin/route.ts](../../frontend/app/api/auth/signin/route.ts)

```typescript
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const SPRING_BOOT_URL = getBackendUrl();
    const userAgent = request.headers.get('user-agent') || 'unknown';  // ← ADD THIS
    
    const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/signin`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': userAgent,  // ← ADD THIS
      },
      credentials: 'include',
      body: JSON.stringify(body),
    });
```

### 2. [app/api/auth/signup/route.ts](../../frontend/app/api/auth/signup/route.ts)

```typescript
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const SPRING_BOOT_URL = getBackendUrl();
    const userAgent = request.headers.get('user-agent') || 'unknown';  // ← ADD THIS
    
    const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/signup`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': userAgent,  // ← ADD THIS
      },
      body: JSON.stringify(body),
    });
```

### 3. [app/api/auth/verify-otp/route.ts](../../frontend/app/api/auth/verify-otp/route.ts)

```typescript
export async function POST(request: NextRequest) {
  try {
    const SPRING_BOOT_URL = getBackendUrl();
    const { email, otp } = await request.json();
    const userAgent = request.headers.get('user-agent') || 'unknown';  // ← ADD THIS
    const params = new URLSearchParams({ email, otp });

    const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/verify-otp?${params.toString()}`, {
      method: "POST",
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': userAgent,  // ← ADD THIS
      },
    });
```

### 4. [app/api/auth/resend-otp/route.ts](../../frontend/app/api/auth/resend-otp/route.ts)

```typescript
export async function POST(request: NextRequest) {
  try {
    const SPRING_BOOT_URL = getBackendUrl();
    const { email } = await request.json();
    const userAgent = request.headers.get('user-agent') || 'unknown';  // ← ADD THIS
    const params = new URLSearchParams({ email });

    const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/resend-otp?${params.toString()}`, {
      method: "POST",
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': userAgent,  // ← ADD THIS
      },
    });
```

### 5. [app/api/auth/reset-password/route.ts](../../frontend/app/api/auth/reset-password/route.ts)

```typescript
export async function POST(request: NextRequest) {
  try {
    const SPRING_BOOT_URL = getBackendUrl();
    const { email, newPassword } = await request.json();
    const userAgent = request.headers.get('user-agent') || 'unknown';  // ← ADD THIS
    
    const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/reset-password`, {
      method: "POST",
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': userAgent,  // ← ADD THIS
      },
      body: JSON.stringify({ email, newPassword }),
    });
```

### 6. [app/api/auth/forgot-password/route.ts](../../frontend/app/api/auth/forgot-password/route.ts)

```typescript
export async function POST(request: NextRequest) {
  try {
    const SPRING_BOOT_URL = getBackendUrl();
    const { email } = await request.json();
    const userAgent = request.headers.get('user-agent') || 'unknown';  // ← ADD THIS
    const params = new URLSearchParams({ email });

    const response = await fetch(`${SPRING_BOOT_URL}/api/auth/public/forgot-password?${params.toString()}`, {
      method: "POST",
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': userAgent,  // ← ADD THIS
      },
    });
```

### 7. [app/api/auth/me/route.ts](../../frontend/app/api/auth/me/route.ts)

```typescript
export async function GET() {
  try {
    const SPRING_BOOT_URL = getBackendUrl();
    const encryptedJwt = (await cookies()).get('jwt_token')?.value;
    const userAgent = (await cookies()).get('user-agent')?.value || 'unknown';  // ← ADD THIS

    if (!encryptedJwt) {
      return NextResponse.json({ /* error response */ }, { status: 401 });
    }

    const rawJwt = decryptToken(encryptedJwt);
    const headers: HeadersInit = {
      'Authorization': `Bearer ${rawJwt}`,
      'User-Agent': userAgent,  // ← ADD THIS
    };

    const response = await fetch(`${SPRING_BOOT_URL}/api/auth/me`, {
      method: "GET",
      headers,
    });
```

---

## Testing After Fix

After implementing the fix:

1. **Clear browser data** to remove old sessions
2. **Login from Windows**
3. **Check database:**
   ```sql
   SELECT device_name, user_agent FROM gs_refresh_tokens 
   WHERE user_id = YOUR_USER_ID;
   ```
4. **Expected result:** device_name should show `"Windows PC"`

---

## Verification Query

```sql
-- Check device names for all sessions
SELECT 
    id,
    user_id,
    device_name,
    user_agent,
    created_at,
    ip_address
FROM gs_refresh_tokens
ORDER BY created_at DESC
LIMIT 10;
```

Expected output for Windows login:
```
| id  | user_id | device_name   | user_agent                            | created_at          | ip_address |
|-----|---------|---------------|---------------------------------------|---------------------|------------|
| 1   | 123     | Windows PC    | Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... | 2025-01-27 10:30:00 | 192.168... |
```
