# OIDC Back-Channel Logout Implementation

## Overview

This document describes the complete implementation of **OpenID Connect Back-Channel Logout 1.0** in this project. Back-channel logout enables the OpenID Provider (OP) to directly notify your application when a user logs out, without requiring any interaction from the user's browser. This ensures that sessions are invalidated even across multiple devices or browsers.

## Table of Contents

1. [What is Back-Channel Logout?](#what-is-back-channel-logout)
2. [Architecture Overview](#architecture-overview)
3. [Configuration](#configuration)
4. [Components](#components)
5. [Flow Diagram](#flow-diagram)
6. [Security Features](#security-features)
7. [Redis Data Model](#redis-data-model)
8. [API Reference](#api-reference)
9. [Testing](#testing)
10. [Troubleshooting](#troubleshooting)

---

## What is Back-Channel Logout?

Back-channel logout is a server-to-server communication mechanism defined in [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html).

### Why Use Back-Channel Logout?

| Feature | Front-Channel Logout | Back-Channel Logout |
|---------|---------------------|---------------------|
| **Requires user's browser** | Yes | No |
| **Can logout all devices** | No (only current browser) | Yes |
| **Works if browser is closed** | No | Yes |
| **Affected by ad-blockers** | Yes | No |
| **Real-time notification** | Yes | Yes |

### Use Cases

1. **Single Sign-Out (SSO)**: When a user logs out from one application, all other applications are notified
2. **Admin-initiated logout**: An administrator can revoke a user's session across all applications
3. **Security events**: Logout triggered by suspicious activity detected by the OP

---

## Architecture Overview

```
┌─────────────────┐      POST       ┌─────────────────────────────────┐
│   OIDC Provider │  ──────────────> │   /auth/backchannel-logout      │
│   (Keycloak,    │  logout_token   │   Next.js Route Handler         │
│    Auth0, etc)  │                 │                                 │
└────────┬────────┘                 │  1. Receive logout_token        │
         │                          │  2. Validate JWT signature       │
         │                          │  3. Validate claims (iss, aud)   │
         │                          │  4. Check JTI replay cache       │
         │                          │  5. Invalidate sessions in Redis │
         │                          │  6. Return 200 OK               │
         │                          └─────────────────────────────────┘
         │                                                     │
         │                                                     ▼
         │                                          ┌──────────────────┐
         │                                          │     Redis        │
         │                                          │  Session Registry│
         │                                          │                  │
         │                                          │ - Invalidate sid  │
         │                                          │ - Invalidate sub  │
         │                                          └──────────────────┘
         │                                                     │
         ▼                                                     ▼
   User logs out                                    User's next request
                                                         checks Redis
                                                              │
                                                         Session invalid
                                                              ▼
                                                     Redirect to login
```

---

## Configuration

### Required Environment Variables

Add the following to your `.env.local`:

```env
# Redis connection for session registry (REQUIRED for back-channel logout)
REDIS_URL=redis://localhost:6379
# Or for Redis with TLS:
# REDIS_URL=rediss://your-redis-server:6379
```

### Provider Registration

When registering your OIDC client with the provider, include:

```json
{
  "backchannel_logout_uri": "https://yourapp.com/auth/backchannel-logout",
  "backchannel_logout_session_required": true
}
```

**Important**: The `backchannel_logout_uri` must be:

- HTTPS in production
- Reachable from the OP (not behind firewalls)
- Exactly match the route in your application

---

## Components

### 1. Route Handler

**File**: `src/app/auth/backchannel-logout/route.ts`

This is the endpoint that receives logout notifications from the OP.

```typescript
// POST /auth/backchannel-logout
export async function POST(request: Request) {
  // Parse form-urlencoded body
  const formData = await request.formData();
  const logoutToken = formData.get('logout_token');

  // Validate logout token
  const result = await validateLogoutToken(logoutToken);

  // Process logout (invalidate sessions)
  const { invalidatedCount, type } = await processLogout(result.claims);

  // Return 200 OK per spec
  return new Response(null, { status: 200 });
}
```

### 2. Logout Token Validator

**File**: `src/lib/oidc/backchannel-logout.ts`

Validates the logout token per the OpenID Connect Back-Channel Logout 1.0 spec:

```typescript
export async function validateLogoutToken(
  logoutToken: string
): Promise<LogoutTokenValidationResult>
```

**Validation Steps**:

1. Decode JWT and extract header/payload
2. Fetch JWKS from provider
3. Verify JWT signature using provider's public keys
4. Validate required claims: `iss`, `aud`, `iat`, `jti`, `events`
5. Verify issuer matches configured issuer
6. Verify audience includes client_id
7. Verify `events` contains backchannel-logout URI
8. Check JTI hasn't been used before (replay protection)
9. Mark JTI as used

### 3. Session Registry

**File**: `src/lib/oidc/session-registry.ts`

Redis-based session registry for tracking active sessions.

```typescript
export class RedisSessionRegistry implements SessionRegistryStorage
```

**Key Operations**:

| Method | Description |
|--------|-------------|
| `register(entry)` | Register a new session |
| `invalidateBySid(sid)` | Invalidate a specific session |
| `invalidateBySub(sub, provider)` | Invalidate all sessions for a user |
| `isValid(sid)` | Check if a session is still valid |
| `isJtiUsed(jti)` | Check if JTI was used (replay protection) |
| `markJtiUsed(jti, expiresAt)` | Mark JTI as used |

### 4. Session Integration

**Files**: `src/lib/oidc/session.ts`, `src/lib/oidc/cookies.ts`

When a user authenticates:

```typescript
export function createSessionData(
  tokens: TokenResponse,
  claims: IDTokenClaims,
  provider: string
): SessionData {
  // Generate or use existing session ID
  const sid = claims.sid || generateSessionId();

  // Register in Redis for back-channel logout
  const registry = getSessionRegistrySafe();
  if (registry) {
    registry.register({
      sub: claims.sub,
      sid,
      provider,
      createdAt: Date.now(),
      expiresAt: tokens.expires_at,
    });
  }

  return {
    ...sessionData,
    sid, // Include in cookie for validation
  };
}
```

When retrieving a session:

```typescript
export async function getSessionCookie(): Promise<SessionData | undefined> {
  const session = await getCookie(COOKIE_NAMES.SESSION);

  // Check if session was invalidated via back-channel logout
  if (session?.sid) {
    const registry = await getRegistry();
    if (registry && !(await registry.isValid(session.sid))) {
      // Session was invalidated - return undefined
      console.log('Session invalidated via backchannel logout');
      return undefined;
    }
  }

  return session;
}
```

### 5. Type Definitions

**File**: `src/lib/oidc/types.ts`

```typescript
// Logout Token Claims
export interface LogoutTokenClaims {
  iss: string;              // Issuer (must match OP)
  aud: string | string[];   // Audience (must include client_id)
  iat: number;              // Issued at time
  jti: string;              // JWT ID (unique, for replay protection)
  events: LogoutEvents;     // Must contain backchannel-logout event
  sub?: string;             // Subject (user ID)
  sid?: string;             // Session ID (optional, for session-specific logout)
  exp?: number;             // Expiration time (optional)
}

// Session Registry Entry
export interface SessionRegistryEntry {
  sub: string;              // User ID
  sid: string;              // Session ID
  provider: string;         // Issuer URL
  createdAt: number;        // Creation timestamp (ms)
  expiresAt: number;        // Expiration timestamp (ms)
}
```

---

## Flow Diagram

### Complete Authentication and Logout Flow

```
┌──────────────┐   1. GET /auth/login    ┌──────────────┐
│   Browser    │ ───────────────────────> │  Next.js App │
└──────────────┘                          └──────┬───────┘
                                                 │
                                                 ▼
                                          ┌──────────────┐
                                          │ OIDC Provider│
                                          └──────┬───────┘
                                                 │
                                                 ▼
┌──────────────┐   2. Redirect with code  ┌──────────────┐
│   Browser    │ <──────────────────────── │  Next.js App │
└──────────────┘   (POST /auth/callback)   └──────┬───────┘
                                                 │
                                                 │ 3. Exchange code for tokens
                                                 │ 4. Get ID token with sid claim
                                                 ▼
                                          ┌──────────────┐
                                          │     Redis    │
                                          │  Register:   │
                                          │  sid=abc123  │
                                          │  sub=user456 │
                                          └──────────────┘
                                                 │
                                                 ▼
┌──────────────┐   5. Set session cookie   ┌──────────────┐
│   Browser    │ <──────────────────────── │  Next.js App │
│              │   (with sid=abc123)       └──────────────┘
└──────────────┘

                              ... Time passes ...

┌──────────────┐   6. User logs out        ┌──────────────┐
│   Browser    │ ───────────────────────> │ OIDC Provider│
└──────────────┘                          └──────┬───────┘
                                                 │
                                                 │ 7. POST logout_token
                                                 ▼
┌──────────────┐   8. Server-to-server    ┌──────────────┐
│ OIDC Provider│ ───────────────────────> │  Next.js App │
│              │   (POST /auth/           │  /backchannel │
│              │    backchannel-logout)   │    -logout    │
└──────────────┘                          └──────┬───────┘
                                                 │
                                                 │ 9. Validate JWT
                                                 │ 10. Check JTI replay
                                                 ▼
                                          ┌──────────────┐
                                          │     Redis    │
                                          │  Mark sid as │
                                          │ invalidated  │
                                          └──────────────┘

┌──────────────┐   11. Next request       ┌──────────────┐
│   Browser    │ ───────────────────────> │  Next.js App │
└──────────────┘   (Cookie: sid=abc123)   └──────┬───────┘
                                                 │
                                                 │ 12. Check Redis
                                                 ▼
                                          ┌──────────────┐
                                          │     Redis    │
                                          │  Session not │
                                          │    valid!    │
                                          └──────────────┘
                                                 │
                                                 ▼
┌──────────────┐   13. Redirect to login  ┌──────────────┐
│   Browser    │ <──────────────────────── │  Next.js App │
└──────────────┘                          └──────────────┘
```

---

## Security Features

### 1. Replay Attack Protection (JTI Cache)

Every logout token contains a unique `jti` (JWT ID) claim. To prevent replay attacks:

```typescript
// Before processing logout, check if JTI was used
const jtiUsed = await registry.isJtiUsed(claims.jti);
if (jtiUsed) {
  return { valid: false, error: 'Replay attack detected' };
}

// Mark JTI as used
await registry.markJtiUsed(claims.jti, expirationTime);
```

**JTI Storage in Redis**:

- Key: `oidc_session:jti:{jti}`
- TTL: 24 hours (matches typical token validity)

### 2. JWT Signature Verification

All logout tokens are verified using the provider's JWKS:

```typescript
const jwks = await fetchJWKS(provider.jwks_uri);
verifyJWTSignature(logoutToken, jwks);
```

### 3. Claim Validation

Required claims are validated:

| Claim | Validation |
|-------|------------|
| `iss` | Must match configured issuer |
| `aud` | Must include client_id |
| `iat` | Must not be in the future (with clock skew) |
| `events` | Must contain `http://schemas.openid.net/event/backchannel-logout` |
| `jti` | Must be unique (not used before) |

### 4. Session Validation

Every request checks if the session was invalidated:

```typescript
const isValid = await registry.isValid(session.sid);
if (!isValid) {
  // Session was invalidated via backchannel logout
  return undefined;
}
```

---

## Redis Data Model

### Key Structure

| Pattern | Description | TTL |
|---------|-------------|-----|
| `oidc_session:s:{sid}` | Session data hash | Session expiration |
| `oidc_session:s:{sid}:invalidated` | Session invalidation flag | 7 days |
| `oidc_session:jti:{jti}` | JTI replay protection | 24 hours |
| `oidc_session:sub:{sub}` | User's session set (all sids) | Session expiration |

### Example Data

```
# Session entry
HSET oidc_session:s:abc123def456 sub "user123" provider "https://keycloak.example.com" createdAt "1704067200000" expiresAt "1704153600000"

# Session invalidation flag
SET oidc_session:s:abc123def456:invalidated "1" EX 604800

# JTI cache
SET oidc_session:jti:unique-token-id-123 "1" EX 86400

# User's session set
SADD oidc_session:sub:user123 abc123def456 another-session-id
```

---

## API Reference

### validateLogoutToken

```typescript
async function validateLogoutToken(
  logoutToken: string
): Promise<LogoutTokenValidationResult>
```

Validates a logout token from the OP.

**Returns**:

```typescript
{
  valid: boolean;
  claims?: LogoutTokenClaims;
  error?: string;
}
```

### processLogout

```typescript
async function processLogout(
  claims: LogoutTokenClaims
): Promise<LogoutProcessResult>
```

Processes logout by invalidating sessions.

**Returns**:

```typescript
{
  invalidatedCount: number;
  type: 'session' | 'global';  // 'session' if sid present, 'global' otherwise
}
```

### getSessionRegistry

```typescript
function getSessionRegistry(): RedisSessionRegistry
```

Gets the singleton session registry instance.

**Throws**: Error if `REDIS_URL` is not configured.

### supportsBackchannelLogout

```typescript
function supportsBackchannelLogout(
  metadata: OpenIDProviderMetadata
): boolean
```

Checks if the provider supports back-channel logout.

### getBackchannelLogoutUri

```typescript
function getBackchannelLogoutUri(baseUrl?: string): string
```

Returns the back-channel logout URI for client registration.

```typescript
getBackchannelLogoutUri('https://myapp.com');
// Returns: 'https://myapp.com/auth/backchannel-logout'
```

---

## Testing

### Manual Testing

1. **Setup Redis**:

   ```bash
   docker run -p 6379:6379 redis:alpine
   ```

2. **Configure Environment**:

   ```env
   REDIS_URL=redis://localhost:6379
   ```

3. **Login and Get Session ID**:
   - Complete authentication flow
   - Check browser cookies for `oidc_session`
   - Decode to find the `sid` value

4. **Simulate Back-Channel Logout**:

   ```bash
   # Create a test logout token (or extract from OP logs)
   curl -X POST "http://localhost:3000/auth/backchannel-logout" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "logout_token=YOUR_LOGOUT_TOKEN"
   ```

5. **Verify Session Invalidation**:
   - Try to access a protected page
   - Should be redirected to login

### Check Redis State

```bash
# Connect to Redis
redis-cli

# View session data
HGETALL oidc_session:s:YOUR_SESSION_ID

# Check if invalidated
GET oidc_session:s:YOUR_SESSION_ID:invalidated

# View user's sessions
SMEMBERS oidc_session:sub:YOUR_USER_ID

# Check JTI cache
GET oidc_session:jti:YOUR_JTI
```

### Testing with Keycloak

Keycloak is a popular OP that supports back-channel logout:

1. **Enable Back-Channel Logout**:
   - Navigate to Realm Settings > Login
   - Enable "Backchannel Logout"

2. **Configure Client**:
   - Set "Backchannel Logout URL" to your endpoint
   - Enable "Backchannel Logout Session Required"

3. **Test**:
   - Login to your application
   - Open another browser with a different session
   - Logout from one session
   - Verify both sessions are invalidated

---

## Troubleshooting

### "REDIS_URL is required for session registry"

**Cause**: Redis URL is not configured.

**Solution**: Set `REDIS_URL` in your environment:

```env
REDIS_URL=redis://localhost:6379
```

### "Replay attack detected: JTI has already been used"

**Cause**: The logout token was already processed.

**Expected**: This is the correct behavior for replay protection.

### "Session invalidated via backchannel logout"

**Cause**: Your session was invalidated by the OP.

**Expected**: This means back-channel logout is working correctly.

### Provider Not Sending Logout Notifications

**Check**:

1. Provider's `backchannel_logout_supported` metadata is `true`
2. Client registration includes correct `backchannel_logout_uri`
3. Endpoint is reachable from the OP (check firewalls, DNS)
4. Server logs show the POST request

### Session Not Invalidated

**Check**:

1. Session ID (`sid`) matches in Redis
2. `sub` claim in logout token matches session's `sub`
3. Provider is sending correct claims in logout token

### Debug Logging

The implementation includes console logging:

```typescript
console.log('=== BACKCHANNEL LOGOUT REQUEST RECEIVED ===');
console.log('=== BACKCHANNEL LOGOUT TOKEN PAYLOAD ===');
console.log('=== BACKCHANNEL LOGOUT SUCCESS ===');
```

Check server logs for detailed information.

---

## References

- [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 6749 - OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7519 - JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)

---

*Document Version: 1.0*
*Created: 2026-03-20*
*Implementation: OIDC Back-Channel Logout 1.0*
