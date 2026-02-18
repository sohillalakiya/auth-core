/**
 * OIDC Token Exchange
 *
 * Handles the exchange of authorization codes for tokens
 * per RFC 6749 Section 4.1.3 and OpenID Connect Core 1.0 Section 3.1.3.3.
 *
 * @see https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3
 * @see https://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
 * @see https://www.rfc-editor.org/rfc/rfc6749#section-4.1.4
 */

import { getConfig } from './env';
import type { TokenResponse } from './types';
import { OIDC_PARAMS, GRANT_TYPES, HTTP_CONSTANTS } from './constants';

/**
 * Token request parameters for authorization code exchange
 */
export interface TokenRequestOptions {
  /**
   * The authorization code received from the provider
   */
  code: string;

  /**
   * The PKCE code verifier (must match the code_challenge used in auth request)
   */
  codeVerifier: string;

  /**
   * The redirect URI used in the authorization request
   * Must match exactly (including query parameters)
   */
  redirectUri: string;

  /**
   * Optional client ID override
   * Defaults to configured client ID
   */
  clientId?: string;

  /**
   * Optional client secret override
   * Defaults to configured client secret (if available)
   */
  clientSecret?: string;

  /**
   * The token endpoint URL
   * Defaults to discovered provider token endpoint
   */
  tokenEndpoint?: string;
}

/**
 * Token error response from the token endpoint
 */
export interface TokenErrorResponse {
  error: string;
  error_description?: string;
  error_uri?: string;
}

/**
 * Builds the request body for token exchange.
 *
 * Creates the form-encoded request body with all required parameters
 * for exchanging an authorization code for tokens.
 *
 * @param options - Token request options
 * @param config - OIDC environment configuration
 * @returns URL-encoded request body string
 */
function buildTokenRequestBody(
  options: TokenRequestOptions,
  config: ReturnType<typeof getConfig>
): string {
  const params = new URLSearchParams();

  // Required parameters
  params.append(OIDC_PARAMS.GRANT_TYPE, GRANT_TYPES.AUTHORIZATION_CODE);
  params.append(OIDC_PARAMS.CODE, options.code);
  params.append(OIDC_PARAMS.REDIRECT_URI, options.redirectUri);
  params.append('code_verifier', options.codeVerifier);

  // Client ID (always required)
  params.append(OIDC_PARAMS.CLIENT_ID, options.clientId || config.clientId);

  // Client secret (if using post method)
  // For basic auth, this goes in the Authorization header instead
  if (options.clientSecret || config.clientSecret) {
    params.append('client_secret', options.clientSecret || config.clientSecret!);
  }

  return params.toString();
}

/**
 * Builds the request headers for token exchange.
 *
 * @param clientSecret - Optional client secret for basic auth
 * @param clientId - Client ID for basic auth
 * @returns Request headers object
 */
function buildTokenRequestHeaders(
  clientSecret?: string,
  clientId?: string
): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Accept: 'application/json',
  };

  // If client secret is provided, use client_secret_basic authentication
  if (clientSecret && clientId) {
    const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
    headers['Authorization'] = `Basic ${credentials}`;
  }

  return headers;
}

/**
 * Parses and validates the token response.
 *
 * @param response - The fetch response from the token endpoint
 * @returns Parsed token response
 * @throws {Error} If the response is invalid or contains an error
 */
async function parseTokenResponse(response: Response): Promise<TokenResponse> {
  const contentType = response.headers.get('content-type');

  // Check for JSON response
  if (!contentType?.includes('application/json')) {
    throw new Error(
      `Unexpected content type from token endpoint: ${contentType}. Expected application/json`
    );
  }

  const data = await response.json();

  // Check for OAuth error response
  if (data.error) {
    const errorResponse: TokenErrorResponse = data;
    throw new TokenExchangeError(
      errorResponse.error_description || `Token exchange failed: ${errorResponse.error}`,
      errorResponse.error
    );
  }

  // Validate required fields in token response
  const requiredFields = ['access_token', 'token_type', 'id_token'];
  const missingFields = requiredFields.filter((field) => !data[field]);

  if (missingFields.length > 0) {
    throw new Error(
      `Invalid token response: missing required fields: ${missingFields.join(', ')}`
    );
  }

  // Validate token type
  if (data.token_type.toLowerCase() !== 'bearer') {
    throw new Error(`Unsupported token type: ${data.token_type}. Only "Bearer" is supported.`);
  }

  return data as TokenResponse;
}

/**
 * Calculates the access token expiration timestamp.
 *
 * @param expiresIn - Expires in seconds from the token response
 * @returns Unix timestamp (milliseconds) when the token expires
 */
function calculateTokenExpiration(expiresIn: number): number {
  // expiresIn is in seconds, convert to milliseconds
  // Subtract a small buffer (5 seconds) to ensure we refresh before actual expiry
  const bufferSeconds = 5;
  return Date.now() + (expiresIn - bufferSeconds) * 1000;
}

/**
 * Exchanges an authorization code for tokens.
 *
 * This function performs the token endpoint request per RFC 6749:
 * - Uses the authorization code grant type
 * - Includes the PKCE code verifier
 * - Handles client authentication (basic or post)
 * - Returns the token response
 *
 * @param options - Token request options
 * @returns Token response with access_token, refresh_token, id_token, etc.
 * @throws {TokenExchangeError} If the token exchange fails
 * @throws {Error} If the request fails or response is invalid
 *
 * @example
 * ```ts
 * const tokens = await exchangeAuthorizationCode({
 *   code: 'SplxlOBeZQQYbYS6WxSbIA',
 *   codeVerifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
 *   redirectUri: 'http://localhost:3000/auth/callback',
 * });
 * console.log(tokens.access_token);
 * console.log(tokens.id_token);
 * ```
 */
export async function exchangeAuthorizationCode(
  options: TokenRequestOptions
): Promise<TokenResponse> {
  const config = getConfig();

  // Build request
  const body = buildTokenRequestBody(options, config);
  const headers = buildTokenRequestHeaders(
    options.clientSecret || config.clientSecret,
    options.clientId || config.clientId
  );

  const tokenEndpoint = options.tokenEndpoint || config.issuer + '/protocol/openid-connect/token';

  try {
    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers,
      body,
      signal: AbortSignal.timeout(HTTP_CONSTANTS.REQUEST_TIMEOUT),
    });

    if (!response.ok) {
      // Try to parse error response
      let errorMessage = `Token request failed: ${response.status} ${response.statusText}`;
      try {
        const errorData: TokenErrorResponse = await response.json();
        errorMessage = errorData.error_description || `Token exchange failed: ${errorData.error}`;
      } catch {
        // Ignore JSON parse errors, use the status text
      }
      throw new TokenExchangeError(errorMessage, 'http_error');
    }

    const tokenResponse = await parseTokenResponse(response);

    // Calculate expiration timestamp
    if (tokenResponse.expires_in) {
      // We'll add expires_at as a convenience field
      const responseWithExpires = tokenResponse as TokenResponse & { expires_at?: number };
      responseWithExpires.expires_at = calculateTokenExpiration(tokenResponse.expires_in);
    }

    return tokenResponse;
  } catch (error) {
    if (error instanceof TokenExchangeError) {
      throw error;
    }

    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        throw new Error(`Timeout while exchanging authorization code with token endpoint`);
      }
      throw error;
    }

    throw new Error('Unknown error during token exchange');
  }
}

/**
 * Token Exchange Error
 *
 * Thrown when the token endpoint returns an error response.
 */
export class TokenExchangeError extends Error {
  constructor(
    message: string,
    public code?: string
  ) {
    super(message);
    this.name = 'TokenExchangeError';
  }
}

/**
 * Checks if a token has expired.
 *
 * @param expiresAt - Expiration timestamp (milliseconds)
 * @param bufferSeconds - Optional buffer in seconds (default: 300 = 5 minutes)
 * @returns true if the token is expired or will expire soon
 */
export function isTokenExpired(
  expiresAt: number,
  bufferSeconds: number = 300
): boolean {
  return Date.now() > expiresAt - bufferSeconds * 1000;
}

/**
 * Gets the time until token expiration in seconds.
 *
 * @param expiresAt - Expiration timestamp (milliseconds)
 * @returns Seconds until expiration, or 0 if already expired
 */
export function getTokenExpirationTime(expiresAt: number): number {
  const remaining = expiresAt - Date.now();
  return Math.max(0, Math.floor(remaining / 1000));
}

/**
 * Validates a token response structure.
 *
 * @param response - The token response to validate
 * @returns true if valid, false otherwise
 */
export function isValidTokenResponse(response: unknown): response is TokenResponse {
  if (typeof response !== 'object' || response === null) {
    return false;
  }

  const token = response as Record<string, unknown>;

  return (
    typeof token.access_token === 'string' &&
    typeof token.token_type === 'string' &&
    typeof token.id_token === 'string' &&
    (token.expires_in === undefined || typeof token.expires_in === 'number') &&
    (token.refresh_token === undefined || typeof token.refresh_token === 'string') &&
    (token.scope === undefined || typeof token.scope === 'string')
  );
}

/**
 * Token refresh request parameters.
 */
export interface RefreshTokenRequestOptions {
  /**
   * The refresh token received from the provider
   */
  refreshToken: string;

  /**
   * Optional scope to request
   */
  scope?: string;

  /**
   * Optional client ID override
   */
  clientId?: string;

  /**
   * Optional client secret override
   */
  clientSecret?: string;

  /**
   * The token endpoint URL
   */
  tokenEndpoint?: string;
}

/**
 * Builds the request body for token refresh.
 *
 * @param options - Refresh token request options
 * @param config - OIDC environment configuration
 * @returns URL-encoded request body string
 */
function buildRefreshTokenRequestBody(
  options: RefreshTokenRequestOptions,
  config: ReturnType<typeof getConfig>
): string {
  const params = new URLSearchParams();

  // Required parameters
  params.append(OIDC_PARAMS.GRANT_TYPE, GRANT_TYPES.REFRESH_TOKEN);
  params.append('refresh_token', options.refreshToken);

  // Client ID (always required for refresh)
  params.append(OIDC_PARAMS.CLIENT_ID, options.clientId || config.clientId);

  // Optional scope
  if (options.scope) {
    params.append(OIDC_PARAMS.SCOPE, options.scope);
  }

  // Client secret (if using post method)
  if (options.clientSecret || config.clientSecret) {
    params.append('client_secret', options.clientSecret || config.clientSecret!);
  }

  return params.toString();
}

/**
 * Refreshes an access token using a refresh token.
 *
 * This function performs the token refresh request per RFC 6749 Section 6:
 * - Uses the refresh_token grant type
 * - Handles client authentication
 * - Returns new access token and potentially new refresh token
 *
 * @param options - Refresh token request options
 * @returns Token response with new access_token, possibly new refresh_token, etc.
 * @throws {TokenExchangeError} If the refresh fails
 * @throws {Error} If the request fails or response is invalid
 *
 * @example
 * ```ts
 * const tokens = await refreshAccessToken({
 *   refreshToken: session.refresh_token,
 * });
 * console.log(tokens.access_token);
 * ```
 */
export async function refreshAccessToken(
  options: RefreshTokenRequestOptions
): Promise<TokenResponse> {
  const config = getConfig();

  // Build request
  const body = buildRefreshTokenRequestBody(options, config);
  const headers = buildTokenRequestHeaders(
    options.clientSecret || config.clientSecret,
    options.clientId || config.clientId
  );

  const tokenEndpoint = options.tokenEndpoint || config.issuer + '/protocol/openid-connect/token';

  try {
    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers,
      body,
      signal: AbortSignal.timeout(HTTP_CONSTANTS.REQUEST_TIMEOUT),
    });

    if (!response.ok) {
      let errorMessage = `Token refresh failed: ${response.status} ${response.statusText}`;
      try {
        const errorData: TokenErrorResponse = await response.json();
        errorMessage = errorData.error_description || `Token refresh failed: ${errorData.error}`;
      } catch {
        // Ignore JSON parse errors
      }
      throw new TokenExchangeError(errorMessage, 'refresh_failed');
    }

    const tokenResponse = await parseTokenResponse(response);

    // Calculate expiration timestamp
    if (tokenResponse.expires_in) {
      const responseWithExpires = tokenResponse as TokenResponse & { expires_at?: number };
      responseWithExpires.expires_at = calculateTokenExpiration(tokenResponse.expires_in);
    }

    return tokenResponse;
  } catch (error) {
    if (error instanceof TokenExchangeError) {
      throw error;
    }

    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        throw new Error('Timeout while refreshing access token');
      }
      throw error;
    }

    throw new Error('Unknown error during token refresh');
  }
}
