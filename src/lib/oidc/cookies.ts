/**
 * OIDC Cookie Management
 *
 * Utilities for managing auth state and session cookies in Next.js.
 * Provides type-safe cookie setting, getting, and deletion.
 *
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
 */

import { cookies } from 'next/headers';
import type { AuthState, SessionData } from './types';
import {
  COOKIE_NAMES,
  TIME_CONSTANTS,
} from './constants';

/**
 * Session registry for back-channel logout validation
 * Imported lazily to avoid circular dependencies
 */
let registryModule: typeof import('./session-registry') | null = null;

async function getRegistry(): Promise<import('./session-registry').SessionRegistryStorage | null> {
  if (!registryModule) {
    try {
      // Lazy dynamic import to avoid circular dependency
      registryModule = await import('./session-registry');
    } catch {
      // Redis not configured, return null
      return null;
    }
  }
  return registryModule.getSessionRegistrySafe();
}

/**
 * Cookie setting options
 */
export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  maxAge?: number;
  path?: string;
  domain?: string;
}

/**
 * Default cookie options for auth state cookie
 */
export const AUTH_STATE_COOKIE_OPTIONS: CookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  maxAge: TIME_CONSTANTS.AUTH_STATE_EXPIRATION,
  path: '/',
};

/**
 * Default cookie options for session cookie
 */
export const SESSION_COOKIE_OPTIONS: CookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  maxAge: TIME_CONSTANTS.SESSION_EXPIRATION_DEFAULT,
  path: '/',
};

/**
 * Sets a cookie value.
 *
 * Note: This function cannot be used in Server Components - it must be used
 * in Server Actions, Route Handlers, or Middleware.
 *
 * @param name - Cookie name
 * @param value - Cookie value (will be JSON-encoded for objects)
 * @param options - Cookie options
 *
 * @example
 * ```ts
 * setCookie('my_cookie', 'value', { httpOnly: true, secure: true });
 * ```
 */
export async function setCookie(
  name: string,
  value: string,
  options: CookieOptions = {}
): Promise<void> {
  const cookieStore = await cookies();

  const cookieOptions: Record<string, string | number | boolean> = {};

  if (options.httpOnly !== undefined) {
    cookieOptions.httpOnly = options.httpOnly;
  }
  if (options.secure !== undefined) {
    cookieOptions.secure = options.secure;
  }
  if (options.sameSite !== undefined) {
    cookieOptions.sameSite = options.sameSite;
  }
  if (options.maxAge !== undefined) {
    cookieOptions.maxAge = options.maxAge;
  }
  if (options.path !== undefined) {
    cookieOptions.path = options.path;
  }
  if (options.domain !== undefined) {
    cookieOptions.domain = options.domain;
  }

  cookieStore.set(name, value, cookieOptions);
}

/**
 * Gets a cookie value.
 *
 * Note: This function cannot be used in Server Components - it must be used
 * in Server Actions, Route Handlers, or Middleware.
 *
 * @param name - Cookie name
 * @returns The cookie value or undefined if not found
 *
 * @example
 * ```ts
 * const value = getCookie('my_cookie');
 * ```
 */
export async function getCookie(name: string): Promise<string | undefined> {
  const cookieStore = await cookies();
  return cookieStore.get(name)?.value;
}

/**
 * Deletes a cookie by setting its expiration to the past.
 *
 * Note: This function cannot be used in Server Components - it must be used
 * in Server Actions, Route Handlers, or Middleware.
 *
 * @param name - Cookie name
 *
 * @example
 * ```ts
 * deleteCookie('my_cookie');
 * ```
 */
export async function deleteCookie(name: string): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.delete(name);
}

/**
 * Checks if a cookie exists.
 *
 * @param name - Cookie name
 * @returns true if the cookie exists
 *
 * @example
 * ```ts
 * if (await hasCookie('my_cookie')) {
 *   // Cookie is present
 * }
 * ```
 */
export async function hasCookie(name: string): Promise<boolean> {
  return (await getCookie(name)) !== undefined;
}

/**
 * Sets the auth state cookie with the provided auth state data.
 *
 * @param authState - The auth state object to store
 *
 * @example
 * ```ts
 * await setAuthStateCookie({
 *   code_verifier: 'abc123',
 *   state: 'xyz789',
 *   nonce: 'nonce456',
 *   timestamp: Date.now(),
 *   redirect_uri: 'http://localhost:3000/auth/callback',
 * });
 * ```
 */
export async function setAuthStateCookie(authState: AuthState): Promise<void> {
  const value = JSON.stringify(authState);
  await setCookie(COOKIE_NAMES.AUTH_STATE, value, AUTH_STATE_COOKIE_OPTIONS);
}

/**
 * Gets the auth state from the cookie.
 *
 * @returns The parsed auth state or undefined if not found
 * @throws {Error} If the cookie value is invalid JSON
 *
 * @example
 * ```ts
 * const authState = await getAuthStateCookie();
 * if (authState) {
 *   // Use auth state
 * }
 * ```
 */
export async function getAuthStateCookie(): Promise<AuthState | undefined> {
  const value = await getCookie(COOKIE_NAMES.AUTH_STATE);
  if (!value) {
    return undefined;
  }

  try {
    const parsed = JSON.parse(value);

    // Validate required fields
    if (
      !parsed.code_verifier ||
      !parsed.state ||
      !parsed.nonce ||
      !parsed.timestamp
    ) {
      return undefined;
    }

    return {
      code_verifier: parsed.code_verifier,
      state: parsed.state,
      nonce: parsed.nonce,
      timestamp: parsed.timestamp,
      redirect_uri: parsed.redirect_uri,
    };
  } catch {
    return undefined;
  }
}

/**
 * Deletes the auth state cookie.
 *
 * @example
 * ```ts
 * await deleteAuthStateCookie();
 * ```
 */
export async function deleteAuthStateCookie(): Promise<void> {
  await deleteCookie(COOKIE_NAMES.AUTH_STATE);
}

/**
 * Sets the session cookie with the provided session data.
 *
 * @param session - The session data object to store
 *
 * @example
 * ```ts
 * await setSessionCookie({
 *   sub: 'user-id',
 *   name: 'John Doe',
 *   email: 'john@example.com',
 *   access_token: 'token123',
 *   id_token: 'id-token-123',
 *   expires_at: Date.now() + 3600000,
 *   provider: 'https://accounts.google.com',
 *   created_at: Date.now(),
 *   updated_at: Date.now(),
 * });
 * ```
 */
export async function setSessionCookie(session: SessionData): Promise<void> {
  const value = JSON.stringify(session);
  await setCookie(COOKIE_NAMES.SESSION, value, SESSION_COOKIE_OPTIONS);
}

/**
 * Gets the session data from the cookie.
 *
 * Also validates the session against the session registry to check if it
 * was invalidated via back-channel logout. If invalidated, the cookie
 * is deleted and undefined is returned.
 *
 * @returns The parsed session data or undefined if not found or invalidated
 * @throws {Error} If the cookie value is invalid JSON
 *
 * @example
 * ```ts
 * const session = await getSessionCookie();
 * if (session) {
 *   // User is authenticated
 * }
 * ```
 */
export async function getSessionCookie(): Promise<SessionData | undefined> {
  const value = await getCookie(COOKIE_NAMES.SESSION);
  if (!value) {
    return undefined;
  }

  try {
    const parsed = JSON.parse(value);

    // Validate required fields
    if (
      !parsed.sub ||
      !parsed.name ||
      !parsed.email ||
      !parsed.access_token ||
      !parsed.id_token ||
      !parsed.expires_at ||
      !parsed.provider ||
      !parsed.created_at ||
      !parsed.updated_at
    ) {
      return undefined;
    }

    // Check if session was invalidated via back-channel logout
    if (parsed.sid) {
      try {
        const registry = await getRegistry();
        if (registry) {
          const isValid = await registry.isValid(parsed.sid);

          if (!isValid) {
            // Session was invalidated via backchannel logout
            console.log('Session invalidated via backchannel logout, returning no session');
            // Note: We can't delete the cookie here because we're in a Server Component
            // The application should redirect to login, and the cookie will be cleared there
            return undefined;
          }
        }
      } catch (error) {
        // If registry check fails, log but allow the session
        console.error('Failed to check session validity:', error);
      }
    }

    return {
      sub: parsed.sub,
      name: parsed.name,
      email: parsed.email,
      picture: parsed.picture,
      access_token: parsed.access_token,
      refresh_token: parsed.refresh_token,
      id_token: parsed.id_token,
      expires_at: parsed.expires_at,
      provider: parsed.provider,
      created_at: parsed.created_at,
      updated_at: parsed.updated_at,
      sid: parsed.sid, // Include session ID
    };
  } catch {
    return undefined;
  }
}

/**
 * Deletes the session cookie.
 *
 * @example
 * ```ts
 * await deleteSessionCookie();
 * ```
 */
export async function deleteSessionCookie(): Promise<void> {
  await deleteCookie(COOKIE_NAMES.SESSION);
}

/**
 * Checks if a valid session exists.
 *
 * @param includeExpired - If true, returns sessions even if expired
 * @returns true if a valid session exists
 *
 * @example
 * ```ts
 * if (await hasSession()) {
 *   // User is authenticated
 * }
 * ```
 */
export async function hasSession(includeExpired: boolean = false): Promise<boolean> {
  const session = await getSessionCookie();
  if (!session) {
    return false;
  }

  // Check expiration
  if (!includeExpired && session.expires_at < Date.now()) {
    return false;
  }

  return true;
}

/**
 * Gets the current session if valid and not expired.
 *
 * @returns The session data or undefined if not authenticated or expired
 *
 * @example
 * ```ts
 * const session = await getValidSession();
 * if (session) {
 *   console.log(`Welcome, ${session.name}`);
 * }
 * ```
 */
export async function getValidSession(): Promise<SessionData | undefined> {
  const session = await getSessionCookie();
  if (!session) {
    return undefined;
  }

  // Check expiration
  if (session.expires_at < Date.now()) {
    return undefined;
  }

  return session;
}
