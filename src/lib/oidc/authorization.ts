/**
 * OIDC Authorization Request Builder
 *
 * Builds authorization URLs for initiating the OAuth 2.0 / OIDC
 * Authorization Code Flow with PKCE.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationRequest
 * @see https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1
 */

import type { OpenIDProviderMetadata, AuthorizationRequestParams } from './types';
import { OIDC_PARAMS, RESPONSE_TYPES, PROMPT_VALUES } from './constants';
import { createCodeChallengeForRequest } from './pkce';

/**
 * Options for building an authorization request
 */
export interface AuthorizationRequestOptions {
  /**
   * The provider's metadata
   */
  provider: OpenIDProviderMetadata;

  /**
   * Client ID from the provider registration
   */
  clientId: string;

  /**
   * Redirect URI registered with the provider
   */
  redirectUri: string;

  /**
   * PKCE code verifier (will be converted to challenge)
   */
  codeVerifier: string;

  /**
   * State parameter for CSRF protection
   */
  state: string;

  /**
   * Scope string (space-separated)
   * Defaults to 'openid profile email'
   */
  scope?: string;

  /**
   * Nonce parameter for ID token replay protection
   */
  nonce?: string;

  /**
   * Response mode (query, fragment, or form_post)
   * Defaults to 'query' for authorization code flow
   */
  responseMode?: 'query' | 'fragment' | 'form_post';

  /**
   * Prompt value to control auth UI
   */
  prompt?: 'none' | 'login' | 'consent' | 'select_account';

  /**
   * Display value for UI customization
   */
  display?: 'page' | 'popup' | 'touch' | 'wap';

  /**
   * Maximum authentication age in seconds
   */
  maxAge?: number;

  /**
   * User's preferred locales
   */
  uiLocales?: string;

  /**
   * ID token hint for re-authentication
   */
  idTokenHint?: string;

  /**
   * Login hint for pre-filling username
   */
  loginHint?: string;

  /**
   * ACR values for authentication context
   */
  acrValues?: string;

  /**
   * Force re-authentication (adds prompt=login)
   */
  forceReauth?: boolean;
}

/**
 * Builds the authorization URL for the OAuth 2.0 / OIDC flow.
 *
 * This function constructs the complete authorization URL with all required
 * parameters including PKCE challenges for security.
 *
 * @param options - Authorization request options
 * @returns The complete authorization URL
 *
 * @example
 * ```ts
 * const url = buildAuthorizationUrl({
 *   provider: await discoverProvider(),
 *   clientId: 'my-client-id',
 *   redirectUri: 'http://localhost:3000/auth/callback',
 *   codeVerifier: generateCodeVerifier(),
 *   state: generateState(),
 *   nonce: generateNonce(),
 *   scope: 'openid profile email',
 * });
 * // Redirect user to this URL
 * ```
 */
export function buildAuthorizationUrl(options: AuthorizationRequestOptions): string {
  const {
    provider,
    clientId,
    redirectUri,
    codeVerifier,
    state,
    scope = 'openid profile email',
    nonce,
    responseMode,
    prompt,
    display,
    maxAge,
    uiLocales,
    idTokenHint,
    loginHint,
    acrValues,
    forceReauth,
  } = options;

  // Build PKCE challenge from verifier
  const { code_challenge, code_challenge_method } = createCodeChallengeForRequest(
    codeVerifier,
    provider.code_challenge_methods_supported
  );

  // Build base authorization parameters
  const params: AuthorizationRequestParams = {
    response_type: RESPONSE_TYPES.CODE,
    client_id: clientId,
    redirect_uri: redirectUri,
    scope,
    state,
    code_challenge,
    code_challenge_method,
  };

  // Add optional nonce (recommended for ID token validation)
  if (nonce) {
    params.nonce = nonce;
  }

  // Add optional response_mode
  if (responseMode) {
    params.response_mode = responseMode;
  }

  // Add prompt parameter
  const finalPrompt = forceReauth ? PROMPT_VALUES.LOGIN : prompt;
  if (finalPrompt) {
    params.prompt = finalPrompt;
  }

  // Add display parameter
  if (display) {
    params.display = display;
  }

  // Add max_age parameter
  if (maxAge !== undefined) {
    params.max_age = maxAge;
  }

  // Add ui_locales parameter
  if (uiLocales) {
    params.ui_locales = uiLocales;
  }

  // Add id_token_hint parameter
  if (idTokenHint) {
    params.id_token_hint = idTokenHint;
  }

  // Add login_hint parameter
  if (loginHint) {
    params.login_hint = loginHint;
  }

  // Add acr_values parameter
  if (acrValues) {
    params.acr_values = acrValues;
  }

  // Build URL with query parameters
  const url = new URL(provider.authorization_endpoint);

  // Add all parameters to URL
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined) {
      url.searchParams.append(key, String(value));
    }
  });

  return url.toString();
}

/**
 * Builds the authorization URL with force re-authentication.
 *
 * Convenience function that sets prompt=login to force the user
 * to re-authenticate even if they have an active session.
 *
 * @param options - Authorization request options
 * @returns The complete authorization URL
 *
 * @example
 * ```ts
 * const url = buildAuthorizationUrlWithReauth({
 *   provider: await discoverProvider(),
 *   clientId: 'my-client-id',
 *   redirectUri: 'http://localhost:3000/auth/callback',
 *   codeVerifier: generateCodeVerifier(),
 *   state: generateState(),
 *   nonce: generateNonce(),
 * });
 * ```
 */
export function buildAuthorizationUrlWithReauth(
  options: Omit<AuthorizationRequestOptions, 'forceReauth'>
): string {
  return buildAuthorizationUrl({ ...options, forceReauth: true });
}

/**
 * Validates the authorization request parameters.
 *
 * @param options - Authorization request options to validate
 * @throws {Error} If any required parameter is invalid
 *
 * @example
 * ```ts
 * validateAuthorizationRequest({
 *   provider: metadata,
 *   clientId: 'my-client-id',
 *   redirectUri: 'http://localhost:3000/auth/callback',
 *   codeVerifier: verifier,
 *   state: 'abc123',
 * });
 * ```
 */
export function validateAuthorizationRequest(
  options: AuthorizationRequestOptions
): void {
  const errors: string[] = [];

  // Validate required fields
  if (!options.provider?.authorization_endpoint) {
    errors.push('Provider must have authorization_endpoint');
  }

  if (!options.clientId) {
    errors.push('clientId is required');
  }

  if (!options.redirectUri) {
    errors.push('redirectUri is required');
  }

  if (!options.codeVerifier) {
    errors.push('codeVerifier is required');
  }

  if (!options.state) {
    errors.push('state is required');
  }

  // Validate URLs
  try {
    if (options.redirectUri) {
      new URL(options.redirectUri);
    }
  } catch {
    errors.push('redirectUri must be a valid URL');
  }

  if (errors.length > 0) {
    throw new Error(
      `Invalid authorization request:\n${errors.map((e) => `  - ${e}`).join('\n')}`
    );
  }
}
