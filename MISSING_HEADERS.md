# Missing Headers: Frontend to Backend Communication

## Summary

Your frontend is **missing critical headers** that the backend expects. Here's what needs to be added:

---

## Required Headers

### 1. **Authorization Header** (CRITICAL)
- **Location:** BFF routes (when calling backend)
- **Format:** `Authorization: Bearer {jwtToken}`
- **Status:** ✅ Partially implemented in some routes
- **Issue:** JWT is encrypted in BFF but needs to be **decrypted** before sending to backend

**Example Implementation in [app/api/admin/user/[userId]/route.ts](app/api/admin/user/[userId]/route.ts):**
```typescript
// Currently (INCOMPLETE):
async function getAuthHeaders(): Promise<HeadersInit> {
    const jwtToken = (await cookies()).get('jwt_token')?.value;
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${jwtToken}`  // ❌ WRONG - This is encrypted!
    };
}
```

**Should be:**
```typescript
import { decryptToken } from '@/lib/api/crypto';

async function getAuthHeaders(): Promise<HeadersInit> {
    const encryptedJwt = (await cookies()).get('jwt_token')?.value;
    if (!encryptedJwt) {
        throw new Error('JWT token not found');
    }
    
    const rawJwt = decryptToken(encryptedJwt);  // ✅ Decrypt first!
    
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${rawJwt}`
    };
}
```

---

### 2. **X-Device-ID Header** (RECOMMENDED)
- **Used by:** Backend for multi-device session management
- **Location:** [RefreshTokenServiceImpl.java line 368](backend/src/main/java/com/rishan/guardianstack/auth/service/impl/RefreshTokenServiceImpl.java#L368)
- **Purpose:** Identify unique device (prevents corporate NAT collisions)
- **Status:** ❌ NOT IMPLEMENTED

**Why needed:** 
- Backend uses device fingerprint = SHA-256(IP + User-Agent + **X-Device-ID**)
- Without it, multiple users on same corporate network get same fingerprint
- Causes false token reuse detection

**Implementation:**
```typescript
// Generate unique device ID (once, stored in browser)
function getOrCreateDeviceId(): string {
    const key = 'device_id';
    let deviceId = localStorage.getItem(key);
    
    if (!deviceId) {
        deviceId = crypto.randomUUID();
        localStorage.setItem(key, deviceId);
    }
    
    return deviceId;
}

// Add to headers:
async function getAuthHeaders(): Promise<HeadersInit> {
    const encryptedJwt = (await cookies()).get('jwt_token')?.value;
    const rawJwt = decryptToken(encryptedJwt);
    const deviceId = getOrCreateDeviceId();
    
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${rawJwt}`,
        'X-Device-ID': deviceId,  // ✅ NEW
    };
}
```

---

### 3. **X-Request-ID Header** (RECOMMENDED)
- **Used by:** Backend for audit logging correlation
- **Location:** [ELKAuditService.java line 165](backend/src/main/java/com/rishan/guardianstack/auth/service/ELKAuditService.java#L165)
- **Purpose:** Track requests through logs
- **Status:** ❌ NOT IMPLEMENTED

**Implementation:**
```typescript
async function getAuthHeaders(): Promise<HeadersInit> {
    const encryptedJwt = (await cookies()).get('jwt_token')?.value;
    const rawJwt = decryptToken(encryptedJwt);
    const deviceId = getOrCreateDeviceId();
    const requestId = crypto.randomUUID();
    
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${rawJwt}`,
        'X-Device-ID': deviceId,
        'X-Request-ID': requestId,  // ✅ NEW
    };
}
```

---

### 4. **User-Agent Header** (AUTOMATICALLY SENT)
- **Status:** ✅ Automatically sent by browser in all requests
- **Used by:** Backend for device fingerprinting, device name parsing
- **No action needed** - browser sends automatically

---

### 5. **X-Forwarded-For & X-Real-IP Headers** (FOR PROXIES)
- **Status:** ⚠️ Only needed if behind reverse proxy
- **Used by:** Backend to get real client IP
- **Automatic:** Only set by reverse proxy (nginx, etc.) - not by frontend
- **Current implementation:** Backend has fallback logic:
  ```java
  // From ELKAuditService.java
  String ip = request.getHeader("X-Forwarded-For");
  if (ip == null || ip.isEmpty()) {
      ip = request.getHeader("X-Real-IP");
  }
  if (ip == null || ip.isEmpty()) {
      ip = request.getRemoteAddr();  // Fallback
  }
  ```

---

## Current Issues

### Issue 1: JWT Token Not Decrypted
**File:** [app/api/admin/user/[userId]/route.ts](app/api/admin/user/[userId]/route.ts#L104)

```typescript
// ❌ WRONG - Sending encrypted token to backend
const jwtToken = (await cookies()).get('jwt_token')?.value;
return {
    'Authorization': `Bearer ${jwtToken}`
};
```

**Result:** Backend JWT validation fails because it receives encrypted token instead of raw JWT

---

### Issue 2: Device Tracking Impossible
**File:** All BFF route files (not implemented anywhere)

Without `X-Device-ID`, backend cannot:
- Track which physical device made the request
- Prevent corporate NAT collisions
- Implement per-device logout
- Enforce device limits (e.g., max 3 devices per ADMIN)

---

### Issue 3: Request Audit Trail Incomplete
**File:** All BFF route files (not implemented anywhere)

Without `X-Request-ID`, backend cannot:
- Correlate frontend→BFF→backend requests in logs
- Troubleshoot request flow issues
- Link Elasticsearch audit logs to specific requests

---

## API Client Enhancement Needed

**File:** [lib/api/api-client.ts](lib/api/api-client.ts)

The main `ApiClient` class also needs enhancement to include these headers:

```typescript
// Current implementation (lines 51-57):
const requestConfig: RequestInit = {
    ...fetchConfig,
    credentials: 'include',
    headers: {
        'Content-Type': 'application/json',
        ...fetchConfig.headers,
    },
};

// Should also include headers like X-Device-ID, X-Request-ID
// But only when forwarding to backend (not for initial BFF requests)
```

---

## Implementation Checklist

### Critical (Must Fix)
- [ ] Decrypt JWT token before sending to backend
  - Edit all BFF route files
  - Use `decryptToken()` from `@/lib/api/crypto`
  
### Recommended (Should Add)
- [ ] Add `X-Device-ID` header
  - Generate once and store in localStorage
  - Include in all authenticated requests
  
- [ ] Add `X-Request-ID` header
  - Generate for each request
  - Include in all requests to backend

- [ ] Create centralized `getAuthHeaders()` utility
  - Single source of truth for auth headers
  - Easier to maintain and update

### Optional
- [ ] Add request/response logging interceptor
- [ ] Add retry logic with exponential backoff
- [ ] Add request timeout handling

---

## Backend Expectations Summary

| Header | Expected By | Purpose | Required? |
|--------|------------|---------|-----------|
| `Authorization` | AuthTokenFilter | JWT validation | ✅ YES |
| `Content-Type` | All endpoints | Parse JSON body | ✅ YES |
| `User-Agent` | RefreshTokenService, ELKAuditService | Device identification, fingerprinting | ✅ Automatic |
| `X-Device-ID` | RefreshTokenService | Device fingerprint generation | ⚠️ Recommended |
| `X-Request-ID` | ELKAuditService | Audit log correlation | ⚠️ Recommended |
| `X-Forwarded-For` | ELKAuditService | Real IP (only if behind proxy) | ❌ No |
| `X-Real-IP` | ELKAuditService | Real IP (only if behind proxy) | ❌ No |

---

## Code Changes Required

### 1. Create Header Utility

**File:** Create [lib/api/headers.ts](lib/api/headers.ts)

```typescript
import { decryptToken } from './crypto';
import { cookies } from 'next/headers';

export function getOrCreateDeviceId(): string {
    if (typeof window === 'undefined') {
        // Server-side: check cookies
        // For now, return placeholder
        return 'server-request';
    }
    
    const key = 'device_id';
    let deviceId = localStorage.getItem(key);
    
    if (!deviceId) {
        deviceId = crypto.randomUUID();
        localStorage.setItem(key, deviceId);
    }
    
    return deviceId;
}

export async function getAuthHeaders(includeDeviceId: boolean = true): Promise<HeadersInit> {
    const cookieStore = await cookies();
    const encryptedJwt = cookieStore.get('jwt_token')?.value;
    
    if (!encryptedJwt) {
        throw new Error('JWT token not found - user not authenticated');
    }
    
    const rawJwt = decryptToken(encryptedJwt);
    
    const headers: HeadersInit = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${rawJwt}`,
        'X-Request-ID': crypto.randomUUID(),
    };
    
    if (includeDeviceId) {
        // For device ID on server-side, generate deterministic ID from JWT subject
        // In real implementation, you might store device ID in cookie
        const deviceId = getOrCreateDeviceId();
        headers['X-Device-ID'] = deviceId;
    }
    
    return headers;
}
```

### 2. Update All BFF Routes

Replace header generation in all `/api/**` route files with:

```typescript
import { getAuthHeaders } from '@/lib/api/headers';

// Instead of:
const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${jwtToken}`
};

// Use:
const headers = await getAuthHeaders();
```

---

## Testing Checklist

After implementing headers:

1. **Login Flow**
   - [ ] Login successfully
   - [ ] JWT is encrypted in cookie
   - [ ] Backend returns 200 OK for `/api/auth/me`

2. **Multi-Device Tracking**
   - [ ] Login on Device A
   - [ ] Login on Device B
   - [ ] Each device has unique X-Device-ID
   - [ ] Backend stores different refresh tokens per device

3. **Request Auditing**
   - [ ] Check Elasticsearch logs
   - [ ] X-Request-ID appears in audit logs
   - [ ] Can correlate requests end-to-end

4. **Error Cases**
   - [ ] Expired JWT returns 401
   - [ ] Invalid JWT returns 401
   - [ ] Missing Authorization header returns 401

---

## Quick Fix Priority

1. **CRITICAL:** Fix JWT decryption (prevents 401 errors)
2. **HIGH:** Add X-Device-ID (prevents session conflicts)
3. **MEDIUM:** Add X-Request-ID (improves debugging)
