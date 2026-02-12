/**
 * OIDC Authorization Login Route
 *
 * Initiates the OAuth 2.0 / OIDC Authorization Code Flow with PKCE.
 * This route handler:
 * 1. Generates state, nonce, and PKCE verifier
 * 2. Stores the auth state in a secure cookie
 * 3. Redirects the user to the provider's authorization endpoint
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationRequest
 * @see https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1
 */

import { redirect } from 'next/navigation';
import { getConfig } from '@/lib/oidc/env';
import { discoverProvider } from '@/lib/oidc/discovery';
import { generatePKCECodePair } from '@/lib/oidc/pkce';
import { generateState, generateNonce, createAuthState } from '@/lib/oidc/state';
import { buildAuthorizationUrl } from '@/lib/oidc/authorization';
import { setAuthStateCookie } from '@/lib/oidc/cookies';
import { ROUTES } from '@/lib/oidc/constants';

/**
 * Query parameters for the login route
 */
interface LoginQueryParams {
  /**
   * Where to redirect after successful authentication
   * Defaults to /user
   */
  redirect_uri?: string;

  /**
   * Force re-authentication (adds prompt=login)
   */
  reauth?: 'true' | 'false';

  /**
   * Custom scopes (space-separated)
   * Defaults to configured scopes
   */
  scope?: string;

  /**
   * ID token hint for re-authentication
   */
  id_token_hint?: string;

  /**
   * Login hint for pre-filling username
   */
  login_hint?: string;
}

/**
 * GET /auth/login
 *
 * Initiates the OIDC authorization flow.
 *
 * Query Parameters:
 * - redirect_uri: Where to redirect after successful auth (default: /user)
 * - reauth: Force re-authentication ("true" or "false")
 * - scope: Custom scopes (space-separated)
 * - id_token_hint: ID token hint for re-authentication
 * - login_hint: Login hint for pre-filling username
 *
 * @param request - The incoming request
 * @returns Redirect to the provider's authorization endpoint
 *
 * @example
 * ```bash
 * # Initiate login with default redirect
 * curl http://localhost:3000/auth/login
 *
 * # Initiate login with custom redirect
 * curl http://localhost:3000/auth/login?redirect_uri=/dashboard
 *
 * # Force re-authentication
 * curl http://localhost:3000/auth/login?reauth=true
 * ```
 */
export async function GET(request: Request) {
  try {
    // Parse query parameters
    const { searchParams } = new URL(request.url);
    const queryParams: LoginQueryParams = {
      redirect_uri: searchParams.get('redirect_uri') || ROUTES.USER,
      reauth: searchParams.get('reauth') === 'true' ? 'true' : 'false',
      scope: searchParams.get('scope') || undefined,
      id_token_hint: searchParams.get('id_token_hint') || undefined,
      login_hint: searchParams.get('login_hint') || undefined,
    };

    // Get OIDC configuration
    const config = getConfig();

    // Discover provider metadata
    const provider = await discoverProvider();

    // Generate PKCE code pair
    const { code_verifier, code_challenge, code_challenge_method } =
      generatePKCECodePair();

    // Generate state and nonce
    const state = generateState();
    const nonce = generateNonce();

    // Calculate the callback redirect URI (full URL)
    const callbackUrl = new URL(config.redirectUri);

    // Create auth state for cookie storage
    const authState = createAuthState(
      code_verifier,
      state,
      nonce,
      queryParams.redirect_uri || ROUTES.USER
    );

    // Store auth state in cookie for verification in callback
    await setAuthStateCookie(authState);

    // Build authorization URL
    const authorizationUrl = buildAuthorizationUrl({
      provider,
      clientId: config.clientId,
      redirectUri: callbackUrl.toString(),
      codeVerifier: code_verifier,
      state,
      nonce,
      scope: queryParams.scope || config.scope,
      forceReauth: queryParams.reauth === 'true',
      idTokenHint: queryParams.id_token_hint,
      loginHint: queryParams.login_hint,
    });

    // Redirect to provider's authorization endpoint
    return redirect(authorizationUrl);
  } catch (error) {
    // Log error and redirect to error page
    console.error('Error initiating authorization flow:', error);

    // Construct error URL with error details
    const errorUrl = new URL(ROUTES.ERROR, process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000');
    errorUrl.searchParams.set('code', 'authorization_error');
    errorUrl.searchParams.set(
      'description',
      error instanceof Error ? error.message : 'Unknown error'
    );

    return redirect(errorUrl.toString());
  }
}
