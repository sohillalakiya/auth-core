/**
 * OIDC Back-Channel Logout Implementation
 *
 * Validates logout tokens and processes session invalidation
 * per OpenID Connect Back-Channel Logout 1.0.
 *
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html
 */

import {
  decodeJWT,
  verifyJWTSignature,
  validateIssuer,
  validateAudience,
  validateIssuedAt,
} from './validation';
import { fetchJWKS } from './jwks';
import { discoverProvider } from './discovery';
import { getConfig } from './env';
import { getSessionRegistry } from './session-registry';
import { BACKCHANNEL_LOGOUT_EVENT_URI } from './constants';
import type {
  LogoutTokenClaims,
  LogoutTokenValidationResult,
  OpenIDProviderMetadata,
} from './types';

/**
 * Logout token validation options
 */
export interface LogoutTokenValidationOptions {
  /** The logout token to validate */
  logoutToken: string;
  /** Clock skew tolerance in seconds (default: 60) */
  clockSkew?: number;
}

/**
 * Validates a logout token per OpenID Connect Back-Channel Logout 1.0 spec.
 *
 * Validation steps:
 * 1. Verify JWT structure (3 parts)
 * 2. Decode and validate header (algorithm)
 * 3. Fetch JWKS from provider
 * 4. Verify signature
 * 5. Validate required claims: iss, aud, iat, jti, events
 * 6. Verify aud contains client_id
 * 7. Verify events contains backchannel-logout URI
 * 8. Check jti not used before (replay protection)
 * 9. Mark jti as used
 *
 * @param logoutToken - The logout token (JWT string)
 * @returns Validation result with claims if successful
 *
 * @example
 * ```ts
 * const result = await validateLogoutToken(logoutToken);
 * if (result.valid) {
 *   console.log('Logout for user:', result.claims.sub);
 * } else {
 *   console.error('Invalid logout token:', result.error);
 * }
 * ```
 */
export async function validateLogoutToken(
  logoutToken: string
): Promise<LogoutTokenValidationResult> {
  try {
    // 1. Decode JWT
    const { header, payload } = decodeJWT(logoutToken);

    // DEBUG: Log the payload to see what Keycloak is sending
    console.log('=== BACKCHANNEL LOGOUT TOKEN PAYLOAD ===');
    console.log(JSON.stringify(payload, null, 2));

    // 2. Get provider and JWKS
    const provider = await discoverProvider();
    const jwks = await fetchJWKS(provider.jwks_uri);

    // 3. Verify signature
    verifyJWTSignature(logoutToken, jwks);

    // 4. Parse claims
    const claims = payload as unknown as LogoutTokenClaims;

    // 5. Validate required claims
    if (!claims.iss || !claims.aud || !claims.iat || !claims.jti || !claims.events) {
      return {
        valid: false,
        error: 'Missing required claims: iss, aud, iat, jti, events',
      };
    }

    // 6. Validate issuer
    const config = getConfig();
    try {
      validateIssuer(claims.iss, config.issuer);
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : 'Issuer validation failed',
      };
    }

    // 7. Validate audience
    try {
      validateAudience(claims.aud, config.clientId);
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : 'Audience validation failed',
      };
    }

    // 8. Validate iat
    try {
      validateIssuedAt(claims.iat);
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : 'Issued at validation failed',
      };
    }

    // 9. Validate events claim
    if (!claims.events[BACKCHANNEL_LOGOUT_EVENT_URI]) {
      return {
        valid: false,
        error: `Missing required event: ${BACKCHANNEL_LOGOUT_EVENT_URI}`,
      };
    }

    // 10. Check for replay attack (jti)
    const registry = getSessionRegistry();
    const jtiUsed = await registry.isJtiUsed(claims.jti);
    if (jtiUsed) {
      return {
        valid: false,
        error: 'Replay attack detected: JTI has already been used',
      };
    }

    // 11. Mark JTI as used
    // Use exp from token if present, otherwise default to 24 hours
    const jtiExpiry = (claims.exp || claims.iat + 86400) * 1000;
    await registry.markJtiUsed(claims.jti, jtiExpiry);

    return { valid: true, claims };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Result of processing a logout
 */
export interface LogoutProcessResult {
  /** Number of sessions invalidated */
  invalidatedCount: number;
  /** Type of logout: 'session' for specific session, 'global' for all user sessions */
  type: 'session' | 'global';
}

/**
 * Process a logout by invalidating the appropriate sessions.
 *
 * If the logout token contains a sid (session ID), only that specific session is invalidated.
 * If only sub (subject) is present, all sessions for that user are invalidated.
 *
 * @param claims - The validated logout token claims
 * @returns Result indicating how many sessions were invalidated and the logout type
 *
 * @example
 * ```ts
 * const result = await validateLogoutToken(logoutToken);
 * if (result.valid) {
 *   const processResult = await processLogout(result.claims);
 *   console.log(`Invalidated ${processResult.invalidatedCount} session(s)`);
 * }
 * ```
 */
export async function processLogout(
  claims: LogoutTokenClaims
): Promise<LogoutProcessResult> {
  const registry = getSessionRegistry();

  if (claims.sid) {
    // Invalidate specific session
    const count = await registry.invalidateBySid(claims.sid);
    return { invalidatedCount: count, type: 'session' };
  } else if (claims.sub) {
    // Invalidate all sessions for user
    const count = await registry.invalidateBySub(claims.sub, claims.iss);
    return { invalidatedCount: count, type: 'global' };
  }

  // No sid or sub - nothing to invalidate
  return { invalidatedCount: 0, type: 'global' };
}

/**
 * Check if the provider supports back-channel logout.
 *
 * @param metadata - The provider's metadata from discovery
 * @returns true if back-channel logout is supported
 *
 * @example
 * ```ts
 * const provider = await discoverProvider();
 * if (supportsBackchannelLogout(provider)) {
 *   console.log('Back-channel logout is supported');
 * }
 * ```
 */
export function supportsBackchannelLogout(
  metadata: OpenIDProviderMetadata
): boolean {
  return metadata.backchannel_logout_supported === true;
}

/**
 * Get the back-channel logout URI for client registration.
 *
 * Returns the absolute URL of the backchannel logout endpoint
 * based on the application base URL.
 *
 * @param baseUrl - The base URL of the application (optional, uses OIDC_REDIRECT_URI by default)
 * @returns The back-channel logout URI
 *
 * @example
 * ```ts
 * const backchannelUri = getBackchannelLogoutUri('https://myapp.com');
 * // Returns: 'https://myapp.com/auth/backchannel-logout'
 * ```
 */
export function getBackchannelLogoutUri(baseUrl: string = ''): string {
  const base =
    baseUrl ||
    process.env.OIDC_BASE_URL ||
    process.env.OIDC_REDIRECT_URI?.replace('/auth/callback', '') ||
    '';
  return `${base.replace(/\/$/, '')}/auth/backchannel-logout`;
}

// Re-export types for convenience
export type { LogoutTokenClaims, LogoutTokenValidationResult };
