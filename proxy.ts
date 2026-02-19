/**
 * Next.js 16 Proxy - Route Protection
 *
 * Provides authentication proxy for protecting routes.
 * Redirects unauthenticated users to the login page.
 *
 * @see https://nextjs.org/docs/app/building-your-application/routing/middleware
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { ROUTES } from '@/lib/oidc/constants';

/**
 * Routes that require authentication
 */
const PROTECTED_ROUTES = ['/user'];

/**
 * Routes that should never be protected (auth routes, public pages)
 */
const PUBLIC_ROUTES = [
  '/',
  '/auth/login',
  '/auth/callback',
  '/auth/error',
  '/auth/logout',
  '/api/auth',
];

/**
 * Checks if a route is public (doesn't require authentication)
 *
 * @param pathname - The route pathname to check
 * @returns true if the route is public
 */
function isPublicRoute(pathname: string): boolean {
  // Exact match for public routes
  if (PUBLIC_ROUTES.includes(pathname)) {
    return true;
  }

  // Check if route starts with any public route prefix
  for (const publicRoute of PUBLIC_ROUTES) {
    if (pathname.startsWith(publicRoute)) {
      return true;
    }
  }

  return false;
}

/**
 * Checks if a route requires authentication
 *
 * @param pathname - The route pathname to check
 * @returns true if the route is protected
 */
function isProtectedRoute(pathname: string): boolean {
  for (const protectedRoute of PROTECTED_ROUTES) {
    if (pathname === protectedRoute || pathname.startsWith(protectedRoute + '/')) {
      return true;
    }
  }
  return false;
}

/**
 * Creates a redirect response to the login page
 *
 * @param request - The incoming request
 * @param returnTo - The URL to return to after login
 * @returns Redirect response to login
 */
function redirectToLogin(request: NextRequest, returnTo?: string): NextResponse {
  const loginUrl = new URL(ROUTES.LOGIN, request.url);

  // Store the original URL for post-login redirect
  if (returnTo) {
    loginUrl.searchParams.set('redirect_uri', returnTo);
  }

  const response = NextResponse.redirect(loginUrl);

  // Clear any invalid session cookie
  response.cookies.delete('oidc_session');

  return response;
}

/**
 * Proxy function for route protection
 *
 * This proxy:
 * 1. Checks if the requested route is public or protected
 * 2. For protected routes, validates the session cookie
 * 3. Redirects to login if no valid session exists
 *
 * @param request - The incoming request
 * @returns NextResponse (redirect or continue)
 */
export function proxy(request: NextRequest): NextResponse {
  const { pathname } = request.nextUrl;

  // Skip proxy for non-page routes (API routes, static files, Next.js internals)
  if (
    pathname.startsWith('/_next') ||
    pathname.startsWith('/api') ||
    pathname.includes('.') // static files with extensions
  ) {
    return NextResponse.next();
  }

  // Public routes - continue without authentication
  if (isPublicRoute(pathname)) {
    return NextResponse.next();
  }

  // Protected routes - check for valid session
  if (isProtectedRoute(pathname)) {
    const sessionCookie = request.cookies.get('oidc_session');

    if (!sessionCookie) {
      // No session cookie, redirect to login
      return redirectToLogin(request, pathname);
    }

    try {
      // Parse session cookie
      const session = JSON.parse(sessionCookie.value);

      // Validate session has required fields
      if (!session.sub || !session.access_token || !session.expires_at) {
        return redirectToLogin(request, pathname);
      }

      // Check if session is expired
      const now = Date.now();
      if (session.expires_at < now) {
        // Session expired, redirect to login
        return redirectToLogin(request, pathname);
      }

      // Session is valid, continue to protected route
      return NextResponse.next();
    } catch {
      // Invalid session cookie, redirect to login
      return redirectToLogin(request, pathname);
    }
  }

  // Default: continue without authentication
  return NextResponse.next();
}

/**
 * Configure which routes the proxy should run on
 *
 * matcher allows you to filter Proxy to run on specific paths.
 *
 * @see https://nextjs.org/docs/app/building-your-application/routing/middleware#matcher
 */
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
};
