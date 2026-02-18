/**
 * OIDC Session Management
 *
 * Handles session lifecycle, token refresh, and session validation.
 * Provides utilities for managing authenticated user sessions.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#Rotation
 */

import { discoverProvider } from './discovery';
import { refreshAccessToken, isTokenExpired } from './tokens';
import {
  getSessionCookie,
  setSessionCookie,
  deleteSessionCookie,
} from './cookies';
import { TIME_CONSTANTS } from './constants';
import type { SessionData, TokenResponse } from './types';

/**
 * Result of a session refresh operation
 */
export interface SessionRefreshResult {
  /** Whether the refresh was successful */
  success: boolean;
  /** The updated session data (if successful) */
  session?: SessionData;
  /** Error details (if failed) */
  error?: string;
}

/**
 * Gets a valid session, automatically refreshing tokens if needed.
 *
 * This function checks if the current session has an expired access token
 * and attempts to refresh it using the refresh token (if available).
 *
 * @param forceRefresh - Force a refresh even if token is not expired
 * @returns The valid session data, or undefined if no valid session exists
 *
 * @example
 * ```ts
 * const session = await getValidSession();
 * if (session) {
 *   console.log('User:', session.name);
 * } else {
 *   // Redirect to login
 * }
 * ```
 */
export async function getValidSessionWithRefresh(
  forceRefresh: boolean = false
): Promise<SessionData | undefined> {
  const session = await getSessionCookie();
  if (!session) {
    return undefined;
  }

  // Check if access token is expired or will expire soon
  const shouldRefresh = forceRefresh || isTokenExpired(
    session.expires_at,
    TIME_CONSTANTS.TOKEN_REFRESH_WINDOW
  );

  if (shouldRefresh) {
    // Check if we have a refresh token
    if (!session.refresh_token) {
      // No refresh token available, delete session
      await deleteSessionCookie();
      return undefined;
    }

    // Attempt to refresh the token
    const result = await refreshSessionTokens(session);

    if (result.success && result.session) {
      return result.session;
    }

    // Refresh failed, delete session
    await deleteSessionCookie();
    return undefined;
  }

  return session;
}

/**
 * Refreshes the tokens in a session using the refresh token.
 *
 * @param session - The current session data
 * @returns Refresh result with updated session or error
 */
export async function refreshSessionTokens(
  session: SessionData
): Promise<SessionRefreshResult> {
  if (!session.refresh_token) {
    return {
      success: false,
      error: 'No refresh token available',
    };
  }

  try {
    // Discover provider to get token endpoint
    const provider = await discoverProvider();

    // Refresh the access token
    const tokens = await refreshAccessToken({
      refreshToken: session.refresh_token,
      tokenEndpoint: provider.token_endpoint,
    });

    // Update session with new tokens
    const now = Date.now();
    const updatedSession: SessionData = {
      ...session,
      access_token: tokens.access_token,
      id_token: tokens.id_token,
      refresh_token: tokens.refresh_token || session.refresh_token,
      expires_at: (tokens as TokenResponse & { expires_at?: number }).expires_at || Date.now() + tokens.expires_in * 1000,
      updated_at: now,
    };

    // Save updated session
    await setSessionCookie(updatedSession);

    return {
      success: true,
      session: updatedSession,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Token refresh failed',
    };
  }
}

/**
 * Checks if a session exists and is valid.
 *
 * @param session - The session data to check
 * @returns true if the session is valid (not expired)
 */
export function isSessionValid(session: SessionData): boolean {
  return session.expires_at > Date.now();
}

/**
 * Checks if a session should be refreshed.
 *
 * @param session - The session data to check
 * @param refreshWindow - Window in seconds before expiry to trigger refresh (default: 5 minutes)
 * @returns true if the session should be refreshed
 */
export function shouldRefreshSession(
  session: SessionData,
  refreshWindow: number = TIME_CONSTANTS.TOKEN_REFRESH_WINDOW
): boolean {
  return isTokenExpired(session.expires_at, refreshWindow);
}

/**
 * Gets the time until session expiration in seconds.
 *
 * @param session - The session data
 * @returns Seconds until expiration, or 0 if expired
 */
export function getSessionExpirationTime(session: SessionData): number {
  const remaining = session.expires_at - Date.now();
  return Math.max(0, Math.floor(remaining / 1000));
}

/**
 * Gets the session age in milliseconds.
 *
 * @param session - The session data
 * @returns Session age in milliseconds
 */
export function getSessionAge(session: SessionData): number {
  return Date.now() - session.created_at;
}

/**
 * Gets the time since last session update in milliseconds.
 *
 * @param session - The session data
 * @returns Time since last update in milliseconds
 */
export function getTimeSinceLastUpdate(session: SessionData): number {
  return Date.now() - session.updated_at;
}

/**
 * Creates a session data object from token response and claims.
 *
 * @param tokens - The token response from the provider
 * @param claims - The validated ID token claims
 * @param provider - The issuer/provider URL
 * @returns Session data object
 */
export function createSessionData(
  tokens: TokenResponse & { expires_at?: number },
  claims: { sub: string; name?: string; email?: string; picture?: string; preferred_username?: string },
  provider: string
): SessionData {
  const now = Date.now();

  return {
    sub: claims.sub,
    name: claims.name || claims.preferred_username || 'Unknown',
    email: claims.email || '',
    picture: claims.picture,
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    id_token: tokens.id_token,
    expires_at: tokens.expires_at || now + tokens.expires_in * 1000,
    provider,
    created_at: now,
    updated_at: now,
  };
}

/**
 * Destroys the current session by deleting the session cookie.
 *
 * @example
 * ```ts
 * await destroySession();
 * ```
 */
export async function destroySession(): Promise<void> {
  await deleteSessionCookie();
}

/**
 * Updates a session with new token data.
 *
 * @param session - The current session data
 * @param tokens - New token response
 * @returns Updated session data
 */
export function updateSessionTokens(
  session: SessionData,
  tokens: TokenResponse & { expires_at?: number }
): SessionData {
  const now = Date.now();

  return {
    ...session,
    access_token: tokens.access_token,
    id_token: tokens.id_token,
    refresh_token: tokens.refresh_token || session.refresh_token,
    expires_at: tokens.expires_at || now + tokens.expires_in * 1000,
    updated_at: now,
  };
}
