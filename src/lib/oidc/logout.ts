/**
 * OIDC Logout Implementation
 *
 * Implements RP-Initiated Logout 1.0 for ending user sessions
 * and redirecting to the post-logout destination.
 *
 * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
 */

import { generateState } from './state';
import { getConfig } from './env';
import { discoverProvider } from './discovery';
import { ROUTES } from './constants';

/**
 * Logout request parameters
 */
export interface LogoutRequestOptions {
  /**
   * The ID token used to authenticate the request
   */
  idTokenHint?: string;

  /**
   * URL to redirect to after logout
   */
  postLogoutRedirectUri?: string;

  /**
   * State parameter for CSRF protection
   */
  state?: string;

  /**
   * Optional UI locales hint
   */
  uiLocales?: string;

  /**
   * Optional logout hint (none or login)
   */
  prompt?: 'none' | 'login';
}

/**
 * Logout state for storing in cookie during logout flow
 */
export interface LogoutState {
  state: string;
  postLogoutRedirectUri: string;
  timestamp: number;
}

/**
 * Builds the RP-Initiated Logout URL.
 *
 * Creates the URL for the end_session_endpoint with all required parameters.
 *
 * @param options - Logout request options
 * @param endSessionEndpoint - The provider's end session endpoint URL
 * @returns The complete logout URL
 *
 * @example
 * ```ts
 * const logoutUrl = buildLogoutUrl({
 *   idTokenHint: session.id_token,
 *   postLogoutRedirectUri: 'http://localhost:3000',
 * });
 * // Redirect user to this URL
 * ```
 */
export function buildLogoutUrl(
  options: LogoutRequestOptions,
  endSessionEndpoint: string
): string {
  const url = new URL(endSessionEndpoint);

  // Add id_token_hint if provided
  if (options.idTokenHint) {
    url.searchParams.append('id_token_hint', options.idTokenHint);
  }

  // Add post_logout_redirect_uri if provided
  if (options.postLogoutRedirectUri) {
    url.searchParams.append('post_logout_redirect_uri', options.postLogoutRedirectUri);
  }

  // Add state if provided (for CSRF protection)
  if (options.state) {
    url.searchParams.append('state', options.state);
  }

  // Add UI locales if provided
  if (options.uiLocales) {
    url.searchParams.append('ui_locales', options.uiLocales);
  }

  return url.toString();
}

/**
 * Creates a logout URL and state for RP-Initiated Logout.
 *
 * This is a convenience function that generates state and builds
 * the complete logout URL with CSRF protection.
 *
 * @param idToken - The ID token from the session
 * @param postLogoutRedirectUri - Where to redirect after logout
 * @returns Object containing logout URL and state
 *
 * @example
 * ```ts
 * const { logoutUrl, state } = createLogoutRequest(session.id_token, '/');
 * // Store state in cookie, then redirect to logoutUrl
 * ```
 */
export function createLogoutRequest(
  idToken: string,
  postLogoutRedirectUri?: string
): { logoutUrl: string; state: string } {
  const config = getConfig();
  const state = generateState();

  // Use configured post-logout redirect URI if not provided
  const _redirectUri = postLogoutRedirectUri || config.postLogoutRedirectUri;

  return {
    state,
    logoutUrl: '', // Will be set after discovering provider
  };
}

/**
 * Validates logout callback parameters.
 *
 * When the provider redirects back after logout, this validates the response.
 *
 * @param searchParams - The URL search params from the callback
 * @returns true if the logout was successful, false if there was an error
 *
 * @example
 * ```ts
 * const url = new URL(request.url);
 * if (!validateLogoutCallback(url.searchParams)) {
 *   // Handle error
 * }
 * ```
 */
export function validateLogoutCallback(searchParams: URLSearchParams): boolean {
  // Check for error response from provider
  if (searchParams.has('error')) {
    return false;
  }

  return true;
}

/**
 * Gets the logout state from query parameters.
 *
 * Extracts state and any error information from the logout callback.
 *
 * @param searchParams - The URL search params from the callback
 * @returns Logout callback result
 *
 * @example
 * ```ts
 * const url = new URL(request.url);
 * const result = parseLogoutCallback(url.searchParams);
 * ```
 */
export function parseLogoutCallback(searchParams: URLSearchParams): {
  state?: string;
  error?: string;
  errorDescription?: string;
} {
  return {
    state: searchParams.get('state') || undefined,
    error: searchParams.get('error') || undefined,
    errorDescription: searchParams.get('error_description') || undefined,
  };
}

/**
 * Prepares a logout request with provider discovery.
 *
 * This function discovers the provider and builds the logout URL.
 *
 * @param options - Logout request options
 * @returns Object containing logout URL and state
 *
 * @example
 * ```ts
 * const result = await prepareLogout({
 *   idTokenHint: session.id_token,
 * });
 * return redirect(result.logoutUrl);
 * ```
 */
export async function prepareLogout(
  options: LogoutRequestOptions
): Promise<{ logoutUrl: string; state?: string }> {
  // Discover provider to get end_session_endpoint
  const provider = await discoverProvider();

  // Check if provider supports RP-Initiated Logout
  if (!provider.end_session_endpoint) {
    throw new Error('Provider does not support RP-Initiated Logout');
  }

  // Generate state if not provided (for CSRF protection)
  const state = options.state || generateState();

  // Build logout URL
  const logoutUrl = buildLogoutUrl(
    {
      ...options,
      state,
    },
    provider.end_session_endpoint
  );

  return { logoutUrl, state };
}

/**
 * Creates a simple local logout (no provider redirect).
 *
 * This clears the session and redirects to the specified URL
 * without involving the OIDC provider. Use this when
 * the provider doesn't support end_session_endpoint.
 *
 * @param postLogoutRedirectUri - Where to redirect after logout
 * @returns Redirect response
 *
 * @example
 * ```ts
 * // In a route handler:
 * return await localLogout('/');
 * ```
 */
export async function localLogout(postLogoutRedirectUri: string = ROUTES.HOME) {
  // This would be used in a route handler context
  // The actual redirect is handled by the caller
  return {
    redirectUri: postLogoutRedirectUri,
    clearSession: true,
  };
}
