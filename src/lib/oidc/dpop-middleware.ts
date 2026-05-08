/**
 * DPoP (Demonstrating Proof-of-Possession) Middleware
 *
 * Server-side middleware for validating DPoP proofs on protected endpoints.
 * RFC 9449: https://www.rfc-editor.org/rfc/rfc9449
 */

import { NextRequest, NextResponse } from 'next/server';
import type { DPoPValidationResult } from './types';
import { verifyDPoPProof, hashAccessToken } from './dpop';

/**
 * DPoP nonce cache for replay protection
 */
const nonceCache = new Map<string, { expiresAt: number }>();
const USED_PROOFS = new Set<string>();
const NONCE_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes
const PROOF_EXPIRY_MS = 60 * 1000; // 1 minute for replay protection

/**
 * Generate a new DPoP nonce
 */
export function generateDPoPNonce(): string {
  const nonce = crypto.randomUUID();
  nonceCache.set(nonce, { expiresAt: Date.now() + NONCE_EXPIRY_MS });
  return nonce;
}

/**
 * Validate a DPoP nonce (check if it exists and hasn't expired)
 */
export function isValidNonce(nonce: string): boolean {
  const entry = nonceCache.get(nonce);
  if (!entry) {
    return false;
  }
  // Nonce is single-use, remove it after validation
  nonceCache.delete(nonce);
  return Date.now() < entry.expiresAt;
}

/**
 * Clean up expired nonces
 */
export function cleanupExpiredNonces(): void {
  const now = Date.now();
  for (const [nonce, entry] of nonceCache.entries()) {
    if (now >= entry.expiresAt) {
      nonceCache.delete(nonce);
    }
  }
}

/**
 * Check if a DPoP proof JTI has been used (replay protection)
 */
function isProofReplay(jti: string): boolean {
  return USED_PROOFS.has(jti);
}

/**
 * Mark a DPoP proof as used
 */
function markProofUsed(jti: string): void {
  USED_PROOFS.add(jti);

  // Clean up old entries periodically
  setTimeout(() => {
    USED_PROOFS.delete(jti);
  }, PROOF_EXPIRY_MS);
}

/**
 * DPoP validation options
 */
export interface DPoPValidationOptions {
  /**
   * The access token being used
   */
  accessToken?: string;
  /**
   * The expected JKT (JWT thumbprint) from the session
   */
  expectedJkt?: string;
  /**
   * Maximum age of the proof in seconds (default: 30)
   */
  maxAgeSeconds?: number;
}

/**
 * Validate DPoP proof from a request
 *
 * @param request - The Next.js request object
 * @param options - Validation options
 * @returns Validation result
 */
export async function validateDPoPFromRequest(
  request: NextRequest,
  options: DPoPValidationOptions = {}
): Promise<DPoPValidationResult> {
  const dpopHeader = request.headers.get('dpop');

  if (!dpopHeader) {
    return {
      valid: false,
      jkt: '',
      error: 'Missing DPoP header',
    };
  }

  // Get the HTTP method and URL for validation
  const htm = request.method;
  const htu = request.url;

  // Verify the DPoP proof
  const result = await verifyDPoPProof(dpopHeader, htu, htm, options.maxAgeSeconds);

  if (!result.valid) {
    return result;
  }

  // Check for replay attacks using JTI
  if (result.payload?.jti && isProofReplay(result.payload.jti)) {
    return {
      valid: false,
      jkt: result.jkt,
      error: 'Replay detected: proof JTI already used',
    };
  }

  // If access token is provided, verify ATH claim
  if (options.accessToken && result.payload) {
    const expectedAth = await hashAccessToken(options.accessToken);
    if (result.payload.ath !== expectedAth) {
      return {
        valid: false,
        jkt: result.jkt,
        error: 'Access token hash mismatch',
      };
    }
  }

  // If expected JKT is provided, verify it matches
  if (options.expectedJkt && result.jkt !== options.expectedJkt) {
    return {
      valid: false,
      jkt: result.jkt,
      error: 'JKT mismatch: proof key does not match session key',
    };
  }

  // Mark the proof as used to prevent replay
  if (result.payload?.jti) {
    markProofUsed(result.payload.jti);
  }

  return result;
}

/**
 * Create a DPoP error response
 *
 * @param error - Error message
 * @param nonce - Optional nonce to include
 * @returns NextResponse with appropriate status and headers
 */
export function createDPoPErrorResponse(
  error: string,
  statusCode: number = 401,
  nonce?: string
): NextResponse {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (nonce) {
    headers['DPoP-Nonce'] = nonce;
  } else {
    // Always include a fresh nonce for retry
    headers['DPoP-Nonce'] = generateDPoPNonce();
  }

  const responseBody = {
    error: statusCode === 401 ? 'invalid_dpop_proof' : 'use_dpop_nonce',
    error_description: error,
  };

  return NextResponse.json(responseBody, { status: statusCode, headers });
}

/**
 * DPoP middleware configuration
 */
export interface DPoPMiddlewareConfig {
  /**
   * Enable/disable DPoP requirement
   */
  enabled?: boolean;
  /**
   * Require DPoP for all requests
   */
  required?: boolean;
  /**
   * Get the expected JKT for the session
   */
  getJkt?: (request: NextRequest) => Promise<string | undefined>;
  /**
   * Get the access token for ATH validation
   */
  getAccessToken?: (request: NextRequest) => Promise<string | undefined>;
  /**
   * Custom validation logic
   */
  customValidation?: (
    request: NextRequest,
    result: DPoPValidationResult
  ) => Promise<boolean>;
}

/**
 * Create a DPoP middleware for Next.js route handlers
 *
 * @param config - Middleware configuration
 * @returns Middleware function
 *
 * @example
 * ```ts
 * export const POST = withDPoP({
 *   required: true,
 *   getJkt: async (req) => {
 *     const session = await getSession(req);
 *     return session?.dpop_jkt;
 *   },
 * })(async (req) => {
 *   // Handle request - DPoP is validated
 *   return NextResponse.json({ success: true });
 * });
 * ```
 */
export function withDPoP<T extends any[]>(
  config: DPoPMiddlewareConfig = {}
) {
  return (
    handler: (request: NextRequest, ...args: T) => Promise<NextResponse>
  ) => {
    return async (request: NextRequest, ...args: T): Promise<NextResponse> => {
      // Clean up expired nonces periodically
      if (Math.random() < 0.1) {
        cleanupExpiredNonces();
      }

      // If DPoP is not enabled, pass through
      if (!config.enabled) {
        return handler(request, ...args);
      }

      // Get JKT and access token for validation
      const expectedJkt = await config.getJkt?.(request);
      const accessToken = await config.getAccessToken?.(request);

      // Validate DPoP proof
      const result = await validateDPoPFromRequest(request, {
        expectedJkt,
        accessToken,
      });

      // Run custom validation if provided
      if (config.customValidation) {
        const customValid = await config.customValidation(request, result);
        if (!customValid) {
          return createDPoPErrorResponse('Custom validation failed');
        }
      }

      // If validation failed, return error
      if (!result.valid) {
        const statusCode = result.error?.includes('nonce') ||
          result.error?.includes('Nonce') ||
          result.error?.includes('expired')
          ? 400
          : 401;

        const nonce = generateDPoPNonce();
        return createDPoPErrorResponse(result.error || 'DPoP validation failed', statusCode, nonce);
      }

      // Store validated JKT in headers for downstream use
      const response = await handler(request, ...args);

      // Add nonce to response for next request
      response.headers.set('DPoP-Nonce', generateDPoPNonce());

      return response;
    };
  };
}

/**
 * Extract DPoP JKT from a request (after validation)
 *
 * @param request - The Next.js request object
 * @returns The JKT from the DPoP proof, or undefined
 */
export async function extractJktFromRequest(request: NextRequest): Promise<string | undefined> {
  const dpopHeader = request.headers.get('dpop');
  if (!dpopHeader) {
    return undefined;
  }

  try {
    const parts = dpopHeader.split('.');
    if (parts.length !== 3) {
      return undefined;
    }

    const header = JSON.parse(atob(parts[0]));
    const jwk = header.jwk;

    if (!jwk) {
      return undefined;
    }

    // Calculate JKT from JWK
    // This is a simplified version - in production, use the full JWK thumbprint calculation
    const canonical = JSON.stringify({
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      y: jwk.y,
    });
    const data = new TextEncoder().encode(canonical);
    const digest = await crypto.subtle.digest('SHA-256', data);
    const hash = new Uint8Array(digest);
    return btoa(String.fromCharCode(...hash))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  } catch {
    return undefined;
  }
}
