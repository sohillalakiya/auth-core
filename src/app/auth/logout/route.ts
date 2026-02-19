/**
 * OIDC Logout Route
 *
 * Implements RP-Initiated Logout 1.0 for ending user sessions.
 * Clears local session and redirects to provider for logout.
 *
 * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
 */

import { redirect } from 'next/navigation';
import { getConfig } from '@/lib/oidc/env';
import { getSessionCookie, deleteSessionCookie } from '@/lib/oidc/cookies';
import { prepareLogout } from '@/lib/oidc/logout';
import { ROUTES } from '@/lib/oidc/constants';

/**
 * Query parameters for the logout route
 */
interface LogoutQueryParams {
  /**
   * Where to redirect after logout (overrides default)
   */
  redirect_uri?: string;

  /**
   * If 'local', skip provider redirect and clear local session only
   */
  method?: 'local' | 'provider';
}

/**
 * GET /auth/logout
 *
 * Initiates the logout flow:
 * 1. Retrieves the current session
 * 2. Clears the session cookie
 * 3. Redirects to provider's end_session_endpoint
 * 4. Provider redirects back to post_logout_redirect_uri
 *
 * Query Parameters:
 * - redirect_uri: Where to redirect after logout (default: home)
 * - method: 'local' to skip provider redirect, 'provider' (default) for full flow
 *
 * @param request - The incoming request
 * @returns Redirect to provider's logout endpoint or direct redirect
 *
 * @example
 * ```bash
 * # Full logout with provider redirect
 * curl http://localhost:3000/auth/logout
 *
 * # Local logout only (no provider redirect)
 * curl http://localhost:3000/auth/logout?method=local
 *
 * # Logout with custom redirect
 * curl http://localhost:3000/auth/logout?redirect_uri=/goodbye
 * ```
 */
export async function GET(request: Request) {
  try {
    // Get the current session
    const session = await getSessionCookie();

    // Parse query parameters
    const { searchParams } = new URL(request.url);
    const queryParams: LogoutQueryParams = {
      redirect_uri: searchParams.get('redirect_uri') || undefined,
      method: (searchParams.get('method') === 'local' ? 'local' : 'provider'),
    };

    // Get the post-logout redirect URI
    const config = getConfig();
    const postLogoutRedirectUri = queryParams.redirect_uri || config.postLogoutRedirectUri;

    // Extract ID token hint from session for provider logout
    const idTokenHint = session?.id_token;

    // Clear the session cookie
    await deleteSessionCookie();

    // Handle local logout (skip provider redirect)
    if (queryParams.method === 'local') {
      return redirect(postLogoutRedirectUri);
    }

    // If no session or no ID token, just redirect
    if (!session || !idTokenHint) {
      return redirect(postLogoutRedirectUri);
    }

    // Prepare provider logout
    const { logoutUrl } = await prepareLogout({
      idTokenHint,
      postLogoutRedirectUri,
    });

    // Redirect to provider's end_session_endpoint
    return redirect(logoutUrl);
  } catch (error) {
    // Log error but still clear session and redirect
    console.error('Error during logout:', error);

    // Ensure session is cleared even on error
    await deleteSessionCookie();

    // Redirect to home page
    return redirect(ROUTES.HOME);
  }
}
