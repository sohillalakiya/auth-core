# Testing Strategy

This document provides a comprehensive testing strategy for the OIDC authentication implementation.

## Overview

The application implements OpenID Connect (OIDC) authentication. This guide provides manual testing checklists and provider testing procedures.

## Manual Testing Checklist

### Authentication Flow

- [ ] **Login flow completes successfully**
  - Navigate to `/`
  - Click "Sign In with OIDC" button
  - Verify redirect to provider's login page
  - Complete authentication on provider
  - Verify redirect back to `/auth/callback`
  - Verify session is created
  - Verify redirect to `/user` page

- [ ] **Invalid state is rejected**
  - Attempt to callback with invalid state parameter
  - Verify error page is shown
  - Verify session is not created

- [ ] **Expired state is rejected**
  - Start authentication flow
  - Wait for state to expire (10 minutes)
  - Complete authentication
  - Verify error page is shown
  - Verify session is not created

- [ ] **Callback handles errors from provider**
  - Simulate error response from provider (`error=access_denied`)
  - Verify error page displays correct message
  - Verify error code is shown
  - Verify retry option is available (if recoverable)

### Token Validation

- [ ] **ID token signature validation works**
  - Complete authentication flow
  - Verify token signature is validated
  - Check logs for signature verification success

- [ ] **ID token claims validation works**
  - Verify `iss` (issuer) claim is validated
  - Verify `aud` (audience) claim contains client_id
  - Verify `exp` (expiration) claim is checked
  - Verify `iat` (issued at) claim is validated
  - Verify `nonce` claim matches

### Session Management

- [ ] **Protected routes redirect to login**
  - Clear cookies
  - Navigate directly to `/user`
  - Verify redirect to `/auth/login`
  - Verify original URL is preserved for post-login redirect

- [ ] **After login, user returns to original page**
  - Navigate to `/user` (should be redirected to login)
  - Note the URL in redirect_uri parameter
  - Complete authentication
  - Verify redirect back to `/user`

- [ ] **Logout clears all session data**
  - Complete authentication
  - Click logout button
  - Verify `oidc_session` cookie is cleared
  - Verify redirect to provider's end_session_endpoint
  - Verify redirect back to homepage

- [ ] **Logout redirects to correct post-logout URL**
  - Complete authentication
  - Click logout
  - Verify final redirect URL is the configured post-logout URL

### Advanced Features

- [ ] **Force re-authentication (prompt=login) works**
  - Use `buildAuthorizationUrlWithReauth()` to create login URL with `prompt=login`
  - Complete authentication
  - Verify new session is created
  - Verify previous session was invalidated

- [ ] **Token refresh works before expiration**
  - Monitor session expiration timestamp
  - Wait until near expiration (within refresh window)
  - Access protected route
  - Verify token is refreshed automatically
  - Verify session cookie is updated with new token

- [ ] **Expired refresh token is handled**
  - Use an expired refresh token
  - Attempt to refresh session
  - Verify error is handled gracefully
  - Verify user is redirected to login

- [ ] **UserInfo endpoint returns correct data**
  - Complete authentication
  - Call `getUserInfoForSession(session.access_token)`
  - Verify user info matches provider records
  - Verify cached user info is returned on subsequent calls

## Provider Testing

### Test with Configured OIDC Provider

1. **Verify discovery endpoint works**
   ```bash
   curl https://{your-issuer}/.well-known/openid-configuration
   ```
   - Verify response returns JSON
   - Verify required endpoints are present:
     - `authorization_endpoint`
     - `token_endpoint`
     - `jwks_uri`
     - `userinfo_endpoint`
     - `end_session_endpoint` (optional)

2. **Verify all endpoints are accessible**
   - Try fetching JWKS from `jwks_uri`
   - Verify response contains `keys` array
   - Verify keys contain `kid` parameter

3. **Verify client credentials work**
   - Check `client_id` is correct
   - If using `client_secret`, verify it matches provider config

### Common Provider-Specific Testing

#### Keycloak

```bash
# Keycloak specific endpoints
https://{keycloak}/realms/{realm}/.well-known/openid-configuration
```

#### Auth0

```bash
# Auth0 specific endpoints
https://{domain}/.well-known/openid-configuration
```

#### Okta

```bash
# Okta specific endpoints
https://{domain}/.well-known/openid-configuration
```

#### Google

```bash
# Google specific endpoints
https://accounts.google.com/.well-known/openid-configuration
```

## Testing Checklist Summary

| Category | Tests | Pass |
|----------|-------|------|
| Authentication Flow | 4 | - |
| Token Validation | 2 | - |
| Session Management | 4 | - |
| Advanced Features | 4 | - |
| Provider Testing | 3 | - |
| **Total** | **17** | **-** |

## Debugging Tips

### Enable Verbose Logging

Add console logs to track authentication flow:

```typescript
// In callback route handler
console.log('Callback params:', searchParams);
console.log('Auth state:', authState);
console.log('Tokens received:', Object.keys(tokens));
console.log('Validation result:', validationResult);
```

### Check Cookie Values

```typescript
// In any Server Component or Route Handler
const { cookies } = await cookies();
console.log('Session cookie:', cookies.get('oidc_session'));
console.log('Auth state cookie:', cookies.get('oidc_auth_state'));
```

### Common Issues

| Issue | Symptom | Solution |
|-------|----------|----------|
| State mismatch | "State parameter does not match" | Clear cookies and try again |
| Invalid token | "Token validation failed" | Check token expiration |
| Provider unreachable | "Failed to discover provider" | Check `OIDC_ISSUER` URL |
| Client not authorized | "Unauthorized client" | Verify client credentials |

## Browser DevTools

### Cookies
- Open DevTools → Application → Cookies
- Check `oidc_session` cookie exists after login
- Verify cookie is `HttpOnly` and `Secure` (in production)
- Check `SameSite` attribute is `Strict`

### Network Tab
- Monitor redirect chain during login
- Verify callback URL includes `code` and `state` parameters
- Check token exchange request headers (Authorization header)

### Console
- Check for JavaScript errors
- Monitor network request failures
- Review authentication logs

## Environment Configuration Testing

### Development Environment

```bash
# Start development server
pnpm dev

# Test at http://localhost:3000
```

### Production Build

```bash
# Build for production
pnpm build

# Test production build locally
pnpm start
```

## Continuous Integration

### GitHub Actions

The CI pipeline automatically runs:
- TypeScript compilation check
- Linting (with disabled react-plugin rules for ESLint 10)

Add to CI:
- End-to-end tests (Playwright/Cypress)
- Unit tests for authentication library
- Integration tests with test provider

## Testing with Test Provider

### Local Testing with Mock Provider

For development, consider using a mock OIDC provider:
- [Mock OAuth 2.0 Provider](https://github.com/navidode/mock-oauth2-server)
- [OIDC Provider Mock](https://github.com/panva/oidc-provider-mock)

### Production Testing

Always test with the actual OIDC provider before deploying:
- Use a test client_id if available
- Verify all scopes are requested correctly
- Test redirect URIs match provider configuration

## Post-Deployment Testing

1. **Smoke Tests**
   - Homepage loads successfully
   - Login button redirects to provider
   - After authentication, user sees dashboard
   - Logout works correctly

2. **Security Tests**
   - Clear session cookie before token expires → should redirect to login
   - Try accessing protected route without session → should redirect to login
   - Verify no tokens in localStorage
   - Verify all cookies are HttpOnly

3. **Cross-Browser Testing**
   - Test in Chrome, Firefox, Safari, Edge
   - Verify cookie behavior across browsers
   - Test private/incognito mode

4. **Mobile Testing**
   - Test on mobile devices
   - Verify responsive design
   - Touch interactions work correctly

## Test Data

### Test User Account

Ensure you have a test user account:
- Email/Username for login
- Known permissions/grants
- Ability to reset if needed

### Test Scenarios

| Scenario | Expected Result |
|----------|----------------|
| Valid login | User is authenticated |
| Invalid credentials | Provider shows error |
| Cancelled login | Error page with access_denied |
| Token expired | Automatic refresh or redirect to login |
| Logout | Session cleared, redirect to provider |
