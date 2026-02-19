# Next.js 16 Best Practices

This document outlines the Next.js 16 best practices implemented in the OIDC authentication system.

## Overview

This application uses Next.js 16 App Router with Server Components by default. All authentication logic runs server-side with no client-side auth state management.

## Project Structure

```
src/
├── app/
│   ├── (auth)/
│   │   ├── login/
│   │   │   └── route.ts           # Route Handler for OAuth initiation
│   │   ├── callback/
│   │   │   └── route.ts           # Route Handler for OAuth callback
│   │   ├── logout/
│   │   │   └── route.ts           # Route Handler for logout
│   │   └── error/
│   │       └── page.tsx           # Server Component error page
│   ├── user/
│   │   └── page.tsx               # Protected user dashboard (Server Component)
│   ├── page.tsx                    # Homepage (Server Component)
│   ├── proxy.ts                    # Next.js 16 middleware for route protection
│   └── layout.tsx                  # Root layout
└── lib/
    └── oidc/                       # OIDC authentication library
```

## Routing Patterns

### Route Handlers vs Server Actions

**Route Handlers** (used for OAuth flows):
- `/auth/login` - Initiates OAuth authorization
- `/auth/callback` - Handles OAuth callback
- `/auth/logout` - Handles RP-Initiated Logout

**Server Components** (used for pages):
- `/` - Homepage
- `/user` - Protected user dashboard
- `/auth/error` - Error page

### Why This Pattern?

OAuth/OIDC requires precise control over HTTP responses (redirects), which Route Handlers provide natively. Server Actions are better suited for form submissions and mutations.

## Middleware (Next.js 16)

Next.js 16 uses `proxy.ts` instead of `middleware.ts` for route protection:

```typescript
// proxy.ts
export function proxy(request: NextRequest): NextResponse {
  // Session validation logic
  // Redirect to login if not authenticated
}
```

**Key features**:
- Edge-compatible session validation
- Protected route patterns
- Redirect URI preservation for post-login

## Cookie Management

All cookie operations use `cookies()` from `next/headers`:

```typescript
import { cookies } from 'next/headers';

// In Server Component or Route Handler
const cookieStore = await cookies();
const session = cookieStore.get('oidc_session');
```

**Benefits**:
- Server-side only (no client access)
- Works in both Server Components and Route Handlers
- HttpOnly flag prevents XSS attacks

## Server Components by Default

All pages are Server Components:
- Direct access to server-side session
- No client-side auth state
- Automatic token refresh capability
- Better performance (no JS bundle for auth logic)

## Authentication Flow

### 1. Login Flow

```
User → /auth/login (Route Handler)
       → Redirects to provider with PKCE challenge
       → Provider redirects to /auth/callback (Route Handler)
       → Validates tokens, creates session
       → Redirects to /user (protected)
```

### 2. Protected Route Access

```
User → /user (protected)
       → proxy.ts validates session
       → If invalid: redirect to /auth/login
       → If valid: serve /user page
```

### 3. Session Validation

Server Components access session directly:

```typescript
import { getSession } from '@/lib/oidc/session';

export default async function UserPage() {
  const session = await getSession();
  // Server-side session access
}
```

## Server Components Best Practices

### Do:
- Fetch session server-side in Server Components
- Use async/await for session operations
- Implement loading states for async operations
- Keep authentication logic server-side

### Don't:
- Use `useEffect` for auth state
- Store tokens in client-side state
- Implement client-side token refresh
- Expose sensitive data to client

## Dynamic Routing

Protected routes use Next.js 16 dynamic routing with middleware:

```typescript
// proxy.ts matcher
export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};
```

This excludes:
- API routes
- Static files
- Next.js internals

## Edge Runtime Compatibility

Current implementation is Node.js compatible. For edge deployment, ensure:

1. Crypto operations are Node.js compatible
2. Cookie encryption uses Node.js crypto module
3. No filesystem operations in hot path

## Performance Considerations

### Session Validation
- Session cookie read on protected routes
- Minimal overhead (cookie read + JSON parse)
- No additional database queries

### Token Refresh
- Refreshes tokens server-side during session validation
- Extends session without user interaction
- Uses background token refresh

### Caching
- Provider metadata cached (5 minutes)
- JWKS cached (5 minutes)
- UserInfo cached (5 minutes)

## Type Safety

Full TypeScript coverage throughout:
- Route handlers are typed
- Server components are typed
- Library exports are typed
- Type definitions for all OIDC types

## Error Handling

Errors are handled server-side with proper logging:
- Secure error logging (sensitive data redacted)
- User-friendly error pages
- HTTP status code mapping
- Error tracking for debugging

## Security Considerations

1. **HttpOnly Cookies** - All session cookies are HttpOnly
2. **SameSite=Strict** - CSRF protection
3. **Secure Flag** - HTTPS-only in production
4. **No localStorage** - Tokens never in browser storage
5. **Encrypted Cookies** - Session data encrypted

## References

- [Next.js 16 Documentation](https://nextjs.org/docs)
- [App Router](https://nextjs.org/docs/app)
- [Route Handlers](https://nextjs.org/docs/app/building-your-application/routing/route-handlers)
- [Server Components](https://nextjs.org/docs/app/building-your-application/rendering/server-components)
- [Dynamic Routing](https://nextjs.org/docs/app/building-your-application/routing/dynamic-routes)
