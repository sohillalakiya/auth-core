/**
 * OIDC Back-Channel Logout Route Handler
 *
 * Receives logout notifications from the OP via server-to-server call.
 * This endpoint is called by the identity provider when a user logs out,
 * allowing the application to invalidate the user's session without
 * involving the user's browser.
 *
 * POST /auth/backchannel-logout
 *
 * Request body (form-urlencoded):
 * - logout_token: JWT signed by the OP containing logout claims
 *
 * Response:
 * - 200 OK: Logout processed successfully
 * - 400 Bad Request: Invalid request or token
 *
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html
 */

import { validateLogoutToken, processLogout } from '@/lib/oidc/backchannel-logout';

/**
 * POST /auth/backchannel-logout
 *
 * Handles back-channel logout notifications from the OpenID Provider.
 *
 * The OP sends a POST request with a logout_token in the form body.
 * We validate the token and invalidate the appropriate sessions.
 *
 * @param request - The incoming HTTP request
 * @returns HTTP response
 *
 * @example
 * ```bash
 * # Example request from OP
 * curl -X POST "https://yourapp.com/auth/backchannel-logout" \
 *   -H "Content-Type: application/x-www-form-urlencoded" \
 *   -d "logout_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
 * ```
 */
export async function POST(request: Request) {
  try {
    console.log('=== BACKCHANNEL LOGOUT REQUEST RECEIVED ===');

    // Parse form-urlencoded body
    const formData = await request.formData();
    const logoutToken = formData.get('logout_token');

    console.log('Logout token present:', !!logoutToken);

    // Validate logout_token parameter
    if (!logoutToken || typeof logoutToken !== 'string') {
      console.error('Missing or invalid logout_token parameter');
      return new Response('Missing logout_token parameter', { status: 400 });
    }

    // Validate logout token (signature, claims, replay protection)
    const result = await validateLogoutToken(logoutToken);

    console.log('Validation result:', result.valid, result.error || 'No error');

    if (!result.valid || !result.claims) {
      // Log error for debugging but don't reveal details to OP
      console.error('Backchannel logout validation failed:', result.error);
      return new Response('Invalid logout_token', { status: 400 });
    }

    // Process logout (invalidate sessions)
    const { invalidatedCount, type } = await processLogout(result.claims);

    // Log for debugging/monitoring
    const subject = result.claims.sub || 'unknown';
    const sessionId = result.claims.sid || 'all';
    console.log(
      `=== BACKCHANNEL LOGOUT SUCCESS === sub="${subject}", sid="${sessionId}", ` +
        `type="${type}", invalidated=${invalidatedCount}`
    );

    // Return 200 OK per spec
    return new Response(null, { status: 200 });
  } catch (error) {
    // Log error for debugging
    console.error('Backchannel logout error:', error);
    return new Response('Invalid request', { status: 400 });
  }
}
