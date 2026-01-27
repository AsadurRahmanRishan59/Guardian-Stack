# Fix Applied: User-Agent Header Forwarding

## Summary

Fixed the issue where device names were showing as **"Unknown Device"** instead of the actual device type (Windows PC, Mac, iPhone, etc.) by forwarding the `User-Agent` header from the browser through the BFF to the backend.

## Root Cause

The Next.js BFF layer was not forwarding the `User-Agent` header when making requests to the Spring Boot backend. Without this header, the backend's device identification logic received `null` and defaulted to "Unknown Device".

## Changes Made

### Auth Routes (All Updated)

✅ [frontend/app/api/auth/signin/route.ts](frontend/app/api/auth/signin/route.ts)
- Added: `const userAgent = request.headers.get('user-agent') || 'unknown';`
- Forward in headers: `'User-Agent': userAgent`

✅ [frontend/app/api/auth/signup/route.ts](frontend/app/api/auth/signup/route.ts)
- Added: `const userAgent = request.headers.get('user-agent') || 'unknown';`
- Forward in headers: `'User-Agent': userAgent`

✅ [frontend/app/api/auth/verify-otp/route.ts](frontend/app/api/auth/verify-otp/route.ts)
- Added: `const userAgent = request.headers.get('user-agent') || 'unknown';`
- Forward in headers: `'User-Agent': userAgent`

✅ [frontend/app/api/auth/resend-otp/route.ts](frontend/app/api/auth/resend-otp/route.ts)
- Added: `const userAgent = request.headers.get('user-agent') || 'unknown';`
- Forward in headers: `'User-Agent': userAgent`

✅ [frontend/app/api/auth/reset-password/route.ts](frontend/app/api/auth/reset-password/route.ts)
- Added: `const userAgent = request.headers.get('user-agent') || 'unknown';`
- Forward in headers: `'User-Agent': userAgent`

✅ [frontend/app/api/auth/forgot-password/route.ts](frontend/app/api/auth/forgot-password/route.ts)
- Added: `const userAgent = request.headers.get('user-agent') || 'unknown';`
- Forward in headers: `'User-Agent': userAgent`

✅ [frontend/app/api/auth/me/route.ts](frontend/app/api/auth/me/route.ts)
- Added: User-Agent extraction from request headers
- Forward in headers: `'User-Agent': userAgent`

### Admin Routes (Enhanced)

✅ [frontend/app/api/admin/user/route.ts](frontend/app/api/admin/user/route.ts)
- Updated `getAuthHeaders(request, nonGet)` to accept request parameter
- Added: User-Agent extraction from request headers
- Updated all calls: `await getAuthHeaders(request, false)` and `await getAuthHeaders(request, true)`

✅ [frontend/app/api/admin/user/[userId]/route.ts](frontend/app/api/admin/user/[userId]/route.ts)
- Updated `getAuthHeaders(request)` to accept request parameter
- Added: User-Agent extraction from request headers
- Updated all calls: `await getAuthHeaders(request)`

## Device Type Recognition (Backend Logic)

The backend's `parseDeviceName()` method now correctly identifies:

```
Windows NT → "Windows PC"
Macintosh → "Mac"
iPhone → "iPhone"
iPad → "iPad"
Android → "Android Device"
Linux → "Linux PC"
Postman → "Postman"
(no match) → "Unknown Device"
```

## Testing

After deploying these changes:

1. **Clear browser cookies** (to remove old sessions)
2. **Log in from Windows**
3. **Check database:**
   ```sql
   SELECT device_name, user_agent 
   FROM gs_refresh_tokens 
   WHERE user_id = YOUR_USER_ID
   LIMIT 1;
   ```
4. **Expected result:** `device_name = "Windows PC"`

## Database Query to Verify

```sql
-- View all your devices with their detected names
SELECT 
    id,
    user_id,
    device_name,
    user_agent,
    created_at,
    ip_address
FROM gs_refresh_tokens
ORDER BY created_at DESC
LIMIT 20;
```

## Files Modified

- 7 auth route files
- 2 admin route files
- **Total:** 9 files updated

All changes are backward compatible and non-breaking.

## Next Steps (Optional)

Consider also forwarding other recommended headers:
- `X-Device-ID` - Unique device identifier (prevents corporate NAT collisions)
- `X-Request-ID` - Request correlation ID for audit trail
- See [MISSING_HEADERS.md](MISSING_HEADERS.md) for details
