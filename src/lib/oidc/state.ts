/**
 * OIDC State and Nonce Management
 *
 * Implements state parameter generation for CSRF protection and
 * nonce generation for ID token replay attack mitigation.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
 * @see https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
 */

import { randomBytes } from 'crypto';
import type { AuthState } from './types';

/**
 * STATE_LENGTH - Number of bytes for random state generation
 * Results in a base64url-encoded string of approximately 43 characters
 */
const STATE_LENGTH = 32;

/**
 * NONCE_LENGTH - Number of bytes for random nonce generation
 * Results in a base64url-encoded string of approximately 43 characters
 */
const NONCE_LENGTH = 32;

/**
 * Generates a cryptographically secure random state parameter.
 *
 * The state parameter is used to mitigate CSRF attacks by correlating
 * the authorization request with the token response.
 *
 * @returns A base64url-encoded random string
 *
 * @example
 * ```ts
 * const state = generateState();
 * ```
 */
export function generateState(): string {
  const buffer = randomBytes(STATE_LENGTH);
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Generates a cryptographically secure nonce parameter.
 *
 * The nonce parameter is used to mitigate replay attacks by correlating
 * the ID token with the authorization request.
 *
 * @returns A base64url-encoded random string
 *
 * @example
 * ```ts
 * const nonce = generateNonce();
 * ```
 */
export function generateNonce(): string {
  const buffer = randomBytes(NONCE_LENGTH);
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Creates an AuthState object for storing in the auth state cookie.
 *
 * This object contains all the temporary data needed during the
 * authorization flow that will be verified in the callback.
 *
 * @param codeVerifier - The PKCE code verifier
 * @param state - The generated state parameter
 * @param nonce - The generated nonce parameter
 * @param redirectUri - The redirect URI used in the request
 * @returns An AuthState object
 *
 * @example
 * ```ts
 * const authState = createAuthState(verifier, state, nonce, redirectUri);
 * ```
 */
export function createAuthState(
  codeVerifier: string,
  state: string,
  nonce: string,
  redirectUri: string
): AuthState {
  return {
    code_verifier: codeVerifier,
    state,
    nonce,
    timestamp: Date.now(),
    redirect_uri: redirectUri,
  };
}

/**
 * Serializes an AuthState object for storage in a cookie.
 *
 * @param authState - The auth state to serialize
 * @returns A JSON string suitable for cookie storage
 *
 * @example
 * ```ts
 * const cookieValue = serializeAuthState(authState);
 * ```
 */
export function serializeAuthState(authState: AuthState): string {
  return JSON.stringify(authState);
}

/**
 * Deserializes an AuthState object from cookie storage.
 *
 * @param data - The serialized auth state string
 * @returns The parsed AuthState object
 * @throws {Error} If the data is invalid JSON
 *
 * @example
 * ```ts
 * const authState = deserializeAuthState(cookieValue);
 * ```
 */
export function deserializeAuthState(data: string): AuthState {
  const parsed = JSON.parse(data);

  // Validate required fields
  if (!parsed.code_verifier || !parsed.state || !parsed.nonce) {
    throw new Error('Invalid auth state: missing required fields');
  }

  return {
    code_verifier: parsed.code_verifier,
    state: parsed.state,
    nonce: parsed.nonce,
    timestamp: parsed.timestamp || Date.now(),
    redirect_uri: parsed.redirect_uri,
  };
}

/**
 * Validates that an auth state has not expired.
 *
 * @param authState - The auth state to validate
 * @param maxAge - Maximum age in milliseconds (default: 10 minutes)
 * @returns true if the state is valid and not expired
 *
 * @example
 * ```ts
 * if (!isAuthStateValid(authState)) {
 *   throw new Error('Auth state has expired');
 * }
 * ```
 */
export function isAuthStateValid(
  authState: AuthState,
  maxAge: number = 10 * 60 * 1000 // 10 minutes
): boolean {
  const now = Date.now();
  const age = now - authState.timestamp;
  return age < maxAge;
}

/**
 * Validates that the state parameter matches the stored value.
 *
 * @param storedState - The state from the auth state cookie
 * @param receivedState - The state from the callback response
 * @returns true if the states match
 * @throws {Error} If the states do not match
 *
 * @example
 * ```ts
 * validateStateMatch(authState.state, callbackParams.state);
 * ```
 */
export function validateStateMatch(
  storedState: string,
  receivedState: string
): void {
  if (storedState !== receivedState) {
    throw new Error(
      'State mismatch: the state parameter does not match the stored value'
    );
  }
}
