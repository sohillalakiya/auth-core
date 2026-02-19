# Security Considerations

This document outlines the security measures implemented in the OIDC authentication system.

## Overview

This application implements OpenID Connect (OIDC) authentication following OAuth 2.0 and OpenID Connect specifications with a focus on security best practices.

## Implemented Security Measures

### 1. State Parameter (CSRF Protection) ✅

**Status**: Implemented in `src/lib/oidc/state.ts` and `src/lib/oidc/cookies.ts`

- Cryptographically secure random state generation (32+ bytes)
- State stored in encrypted HttpOnly cookie
- State validated on callback (prevents CSRF attacks)
- State expiration: 10 minutes
- **Implementation**: `generateState()`, `validateStateMatch()`

### 2. Nonce Parameter (Replay Protection) ✅

**Status**: Implemented in `src/lib/oidc/state.ts` and `src/lib/oidc/validation.ts`

- Cryptographically secure random nonce generation (32+ bytes)
- Nonce included in authorization request
- Nonce validated in ID token claims
- **Implementation**: `generateNonce()`, `validateNonce()`

### 3. PKCE (Proof Key for Code Exchange) ✅

**Status**: Implemented in `src/lib/oidc/pkce.ts` and `src/lib/oidc/authorization.ts`

- SHA-256 code challenge method (S256)
- Code verifier generated for each authentication request
- Code verifier stored in encrypted cookie
- Verifier validated during token exchange
- **Implementation**: `generateCodeVerifier()`, `generateCodeChallengeS256()`

### 4. Token Storage Security ✅

**Status**: Implemented in `src/lib/oidc/cookies.ts`

| Practice | Implementation |
|----------|----------------|
| No localStorage | Tokens stored only in HttpOnly cookies |
| HttpOnly flag | Prevents XSS access to cookies |
| Secure flag | Set in production (HTTPS) |
| SameSite=Strict | Prevents CSRF attacks |
| Encrypted cookies | Session data encrypted |

### 5. ID Token Validation ✅

**Status**: Implemented in `src/lib/oidc/validation.ts`

- JWT signature verification using JWKS
- Required claims validation (iss, sub, aud, exp, iat)
- Issuer validation with trailing slash handling
- Audience validation (including azp for third-party tokens)
- Expiration validation with clock skew tolerance
- **Implementation**: `validateIDToken()`, `verifyJWTSignature()`

### 6. HTTPS Enforcement ✅

**Status**: Implemented in `src/lib/oidc/constants.ts`

- `COOKIE_CONFIG.SECURE` uses true in production
- Environment-based configuration (`NODE_ENV === 'production'`)

## Security Best Practices

### Authorization Code Flow with PKCE

We use the Authorization Code Flow with PKCE (RFC 7636) which:

- Prevents authorization code interception attacks
- Eliminates the need for client secrets in public clients
- Provides the highest security level for browser-based apps

### Session Management

- Sessions stored in encrypted HttpOnly cookies
- Session cookies have SameSite=Strict
- Automatic session expiration
- Token refresh with new PKCE verifier

### Error Handling

- Sensitive data redaction from logs
- No secrets in error messages
- Generic error messages to users

## Security Headers

### Cookie Security

```typescript
Secure: true // Production (HTTPS only)
HttpOnly: true // Prevents XSS access
SameSite: 'strict' // CSRF protection
Path: '/' // Available site-wide
```

## Token Handling

### Access Token
- Used for API calls to UserInfo endpoint
- Stored in encrypted session cookie
- Short-lived (typically 1 hour)
- Auto-refreshed using refresh token

### Refresh Token
- Used to obtain new access tokens
- Stored in encrypted session cookie
- Long-lived (per provider configuration)

### ID Token
- Validated signature and claims
- Not used for API calls
- Contains user identity claims

## Provider Communication

### Discovery
- Provider metadata fetched from well-known endpoint
- Cached for 5 minutes
- Validates required endpoints exist

### JWKS
- Fetched from provider's JWKS endpoint
- Cached for 5 minutes
- Keys matched by kid (Key ID)
- Only RSA keys supported for signature verification

## Environment Variables

### Required
- `OIDC_ISSUER` - Provider issuer URL
- `OIDC_CLIENT_ID` - Client identifier

### Optional
- `OIDC_CLIENT_SECRET` - For confidential clients
- `OIDC_REDIRECT_URI` - Callback URL
- `OIDC_POST_LOGOUT_REDIRECT_URI` - Post-logout redirect
- `OIDC_SCOPE` - Requested scopes

## Threat Mitigation

### CSRF (Cross-Site Request Forgery)
- **Mitigation**: State parameter validation
- **Implementation**: `validateStateMatch()`

### XSS (Cross-Site Scripting)
- **Mitigation**: HttpOnly cookies
- **No sensitive data in JavaScript-accessible storage**

### Replay Attacks
- **Mitigation**: Nonce parameter in ID tokens
- **State parameter for authorization requests
- **One-time use of authorization codes**

### Token Interception
- **Mitigation**: PKCE (RFC 7636)
- **Direct token exchange (no implicit flow)**

### Open Redirects
- **Mitigation**: Validation of redirect URIs
- **Implementation**: Constants-based redirect URLs

### Session Fixation
- **Mitigation**: Session creation timestamp
- **Regenerated on login

## Recommendations

### For Production Deployment

1. **Always use HTTPS** - Required for production
2. **Rotate client secrets regularly**
3. **Monitor token expiration** - Implement refresh logic
4. **Log security events** - Monitor for suspicious activity
5. **Keep dependencies updated** - Regular security updates

### For Development

1. **Use environment-specific configurations**
2. **Test with different providers**
3. **Verify all security headers in browser DevTools**

## References

- [RFC 6749 - OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7636 - PKCE](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 7519 - JWT](https://www.rfc-editor.org/rfc/rfc7519)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [OWASP OAuth 2.0 Security](https://cheatsheetseries.owasp.org/cheatsheets/OAuth_2_0_Security_Cheat_Sheet.html)
