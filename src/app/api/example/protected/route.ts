/**
 * Example Protected API Route with DPoP
 *
 * This demonstrates how to protect an API endpoint using DPoP (RFC 9449).
 *
 * The endpoint validates that:
 * 1. A valid DPoP proof is provided
 * 2. The proof's JKT matches the session's stored DPoP key
 * 3. The proof's ATH (if included) matches the access token
 *
 * @see https://www.rfc-editor.org/rfc/rfc9449
 */

import { NextRequest, NextResponse } from 'next/server';
import { withDPoP } from '@/lib/oidc/dpop-middleware';
import { getSession } from '@/lib/oidc/session';

/**
 * GET /api/example/protected
 *
 * Protected endpoint that requires DPoP proof.
 *
 * Usage:
 * ```ts
 * const response = await dpopFetch('/api/example/protected', {
 *   accessToken: session.access_token,
 *   method: 'GET',
 * });
 * ```
 */
export const GET = withDPoP({
  enabled: true, // Enable DPoP validation
  required: true, // Require DPoP proof
  getJkt: async () => {
    const session = await getSession();
    return session?.dpop_jkt;
  },
  getAccessToken: async () => {
    const session = await getSession();
    return session?.access_token;
  },
})(async () => {
  const session = await getSession();

  return NextResponse.json({
    message: 'Protected resource accessed successfully',
    user: {
      sub: session?.sub,
      name: session?.name,
      email: session?.email,
    },
    timestamp: new Date().toISOString(),
  });
});

/**
 * POST /api/example/protected
 *
 * Protected POST endpoint with DPoP validation.
 *
 * Usage:
 * ```ts
 * const response = await dpopFetch('/api/example/protected', {
 *   accessToken: session.access_token,
 *   method: 'POST',
 *   headers: {
 *     'Content-Type': 'application/json',
 *   },
 *   body: JSON.stringify({ message: 'Hello' }),
 * });
 * ```
 */
export const POST = withDPoP({
  enabled: true,
  required: true,
  getJkt: async () => {
    const session = await getSession();
    return session?.dpop_jkt;
  },
  getAccessToken: async () => {
    const session = await getSession();
    return session?.access_token;
  },
})(async (request: NextRequest) => {
  const session = await getSession();
  const body = await request.json();

  return NextResponse.json({
    message: 'Protected POST request successful',
    user: {
      sub: session?.sub,
      name: session?.name,
    },
    receivedData: body,
    timestamp: new Date().toISOString(),
  });
});
