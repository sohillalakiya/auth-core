/**
 * OIDC Authorization Callback Route
 *
 * Handles the callback from the OIDC provider after user authentication.
 * This route handler:
 * 1. Extracts code and state from query parameters
 * 2. Validates state parameter (CSRF protection)
 * 3. Exchanges authorization code for tokens
 * 4. Validates ID token (signature, claims, nonce)
 * 5. Processes token response and creates session
 * 6. Redirects to the original destination
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#Authentication
 * @see https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2
 */

import { redirect } from 'next/navigation';
import { getConfig } from '@/lib/oidc/env';
import { discoverProvider } from '@/lib/oidc/discovery';
import { exchangeAuthorizationCode, TokenExchangeError } from '@/lib/oidc/tokens';
import { validateIDToken, type IDTokenValidationResult } from '@/lib/oidc/validation';
import {
  getAuthStateCookie,
  deleteAuthStateCookie,
  setSessionCookie,
} from '@/lib/oidc/cookies';
import { validateStateMatch, isAuthStateValid } from '@/lib/oidc/state';
import { ROUTES, TIME_CONSTANTS, AUTHORIZATION_ERROR_CODES, APP_ERROR_CODES } from '@/lib/oidc/constants';
import type { TokenResponse, IDTokenClaims } from '@/lib/oidc/types';

/**
 * Query parameters received from the OIDC provider callback
 */
interface CallbackQueryParams {
  /**
   * The authorization code (successful response)
   */
  code?: string;

  /**
   * The state parameter for CSRF protection
   */
  state?: string;

  /**
   * Error code (error response)
   */
  error?: string;

  /**
   * Human-readable error description
   */
  error_description?: string;

  /**
   * URI with more information about the error
   */
  error_uri?: string;
}

/**
 * Creates a session from the validated token response.
 *
 * Extracts user information and tokens from the token response
 * to create the session data structure.
 *
 * @param tokens - The token response from the provider
 * @param claims - The validated ID token claims
 * @returns Session data object
 */
function createSessionFromTokensAndClaims(
  tokens: TokenResponse,
  claims: IDTokenClaims
): {
  sub: string;
  name: string;
  email: string;
  picture?: string;
  access_token: string;
  refresh_token?: string;
  id_token: string;
  expires_at: number;
  provider: string;
  created_at: number;
  updated_at: number;
} {
  const now = Date.now();
  const config = getConfig();

  return {
    sub: claims.sub,
    name: claims.name || claims.preferred_username || 'Unknown',
    email: claims.email || '',
    picture: claims.picture,
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    id_token: tokens.id_token,
    expires_at: (tokens as TokenResponse & { expires_at?: number }).expires_at || Date.now() + tokens.expires_in * 1000,
    provider: config.issuer,
    created_at: now,
    updated_at: now,
  };
}

/**
 * Validates the callback parameters.
 *
 * Ensures required parameters are present and valid.
 *
 * @param params - The callback query parameters
 * @throws {Error} If validation fails
 */
function validateCallbackParams(params: CallbackQueryParams): void {
  // Check for error response from provider
  if (params.error) {
    const errorMessage =
      params.error_description ||
      `Authorization failed: ${params.error}`;
    throw new Error(errorMessage);
  }

  // Check for required code parameter
  if (!params.code) {
    throw new Error('Missing authorization code in callback response');
  }

  // Check for required state parameter
  if (!params.state) {
    throw new Error('Missing state parameter in callback response');
  }
}

/**
 * Handles ID token validation failure.
 *
 * @param result - The validation result
 * @throws {Error} With appropriate error message
 */
function handleIDTokenValidationError(result: IDTokenValidationResult): never {
  throw new Error(
    result.error || 'ID token validation failed'
  );
}

/**
 * GET /auth/callback
 *
 * Handles the callback from the OIDC provider.
 *
 * Query Parameters:
 * - code: The authorization code (successful auth)
 * - state: The state parameter for CSRF protection
 * - error: Error code (failed auth)
 * - error_description: Error description
 *
 * @param request - The incoming request
 * @returns Redirect to the user's original destination or error page
 *
 * @example
 * ```bash
 * # Successful callback
 * curl "http://localhost:3000/auth/callback?code=SplxlO&state=af0ifjsldkj"
 *
 * # Error callback
 * curl "http://localhost:3000/auth/callback?error=access_denied"
 * ```
 */
export async function GET(request: Request) {
  try {
    // Parse query parameters from callback URL
    const { searchParams } = new URL(request.url);
    const params: CallbackQueryParams = {
      code: searchParams.get('code') || undefined,
      state: searchParams.get('state') || undefined,
      error: searchParams.get('error') || undefined,
      error_description: searchParams.get('error_description') || undefined,
      error_uri: searchParams.get('error_uri') || undefined,
    };

    // Validate callback parameters
    validateCallbackParams(params);

    // Retrieve and validate auth state from cookie
    const authState = await getAuthStateCookie();
    if (!authState) {
      throw new Error(
        'No auth state found. The authentication request may have expired or been tampered with.'
      );
    }

    // Validate state hasn't expired
    if (!isAuthStateValid(authState, TIME_CONSTANTS.AUTH_STATE_EXPIRATION * 1000)) {
      await deleteAuthStateCookie();
      throw new Error(
        'Authentication request has expired. Please try again.'
      );
    }

    // Validate state parameter matches (CSRF protection)
    validateStateMatch(authState.state, params.state!);

    // Get the original redirect URI from config
    const config = getConfig();
    const redirectUri = config.redirectUri;

    // Discover provider metadata
    const provider = await discoverProvider();

    // Exchange authorization code for tokens
    const tokens = await exchangeAuthorizationCode({
      code: params.code!,
      codeVerifier: authState.code_verifier,
      redirectUri,
      tokenEndpoint: provider.token_endpoint,
    });

    // Validate ID token (signature, claims, nonce)
    const validationResult = await validateIDToken({
      idToken: tokens.id_token,
      nonce: authState.nonce,
    });

    if (!validationResult.valid) {
      handleIDTokenValidationError(validationResult);
    }

    // Create session from validated tokens and claims
    const sessionData = createSessionFromTokensAndClaims(
      tokens,
      validationResult.claims!
    );

    // Delete the temporary auth state cookie
    await deleteAuthStateCookie();

    // Set the session cookie
    await setSessionCookie(sessionData);

    // Redirect to the original destination (stored in auth state)
    const destination = authState.redirect_uri || ROUTES.USER;
    return redirect(destination);
  } catch (error) {
    // Log error for debugging
    console.error('Error in callback handler:', error);

    // Build error URL with error details
    const errorUrl = new URL(ROUTES.ERROR, request.url);

    if (error instanceof TokenExchangeError) {
      // Token-specific errors
      errorUrl.searchParams.set('code', 'token_error');
      errorUrl.searchParams.set('error', error.code || 'invalid_grant');
      errorUrl.searchParams.set('description', error.message);
    } else if (error instanceof Error) {
      // General errors
      const errorMessage = error.message;

      // Map error message to error code
      if (errorMessage.includes('state') || errorMessage.includes('CSRF')) {
        errorUrl.searchParams.set('code', AUTHORIZATION_ERROR_CODES.INVALID_REQUEST);
      } else if (errorMessage.includes('expired')) {
        errorUrl.searchParams.set('code', 'state_expired');
      } else if (errorMessage.includes('Missing authorization code')) {
        errorUrl.searchParams.set('code', AUTHORIZATION_ERROR_CODES.INVALID_REQUEST);
      } else if (errorMessage.includes('nonce') || errorMessage.includes('replay')) {
        errorUrl.searchParams.set('code', APP_ERROR_CODES.TOKEN_VALIDATION_ERROR);
      } else if (errorMessage.includes('signature') || errorMessage.includes('JWT')) {
        errorUrl.searchParams.set('code', APP_ERROR_CODES.TOKEN_VALIDATION_ERROR);
      } else if (errorMessage.includes('issuer') || errorMessage.includes('audience')) {
        errorUrl.searchParams.set('code', APP_ERROR_CODES.TOKEN_VALIDATION_ERROR);
      } else {
        errorUrl.searchParams.set('code', 'authorization_error');
      }

      errorUrl.searchParams.set('description', errorMessage);
    } else {
      errorUrl.searchParams.set('code', 'unknown_error');
      errorUrl.searchParams.set('description', 'An unknown error occurred');
    }

    // Redirect to error page
    return redirect(errorUrl.toString());
  }
}
