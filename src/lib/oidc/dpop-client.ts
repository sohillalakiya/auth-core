/**
 * DPoP Client Helper
 *
 * Client-side utilities for making DPoP-protected API requests.
 * Handles DPoP proof generation and nonce management.
 *
 * RFC 9449: https://www.rfc-editor.org/rfc/rfc9449
 */

import type { DPoPKeyPair } from './types';

/**
 * Client-side DPoP state
 */
interface DPoPClientState {
  keyPair: DPoPKeyPair | null;
  nonce: string | null;
  lastNonceTime: number;
}

/**
 * In-memory state for the client
 * In a browser environment, consider persisting to sessionStorage
 */
const state: DPoPClientState = {
  keyPair: null,
  nonce: null,
  lastNonceTime: 0,
};

/**
 * Initialize or get the existing DPoP key pair
 */
export async function getOrCreateDPoPKeyPair(): Promise<DPoPKeyPair> {
  if (!state.keyPair) {
    const { generateDPoPKeyPair } = await import('./dpop');
    state.keyPair = await generateDPoPKeyPair();
  }
  return state.keyPair;
}

/**
 * Update the stored nonce from a response
 */
export function updateDPoPNonce(nonce: string): void {
  state.nonce = nonce;
  state.lastNonceTime = Date.now();
}

/**
 * Get the current nonce (if still valid)
 */
export function getDPoPNonce(): string | undefined {
  // Nonces should be valid for at least a few minutes
  const NONCE_VALIDITY_MS = 5 * 60 * 1000;
  if (state.nonce && Date.now() - state.lastNonceTime < NONCE_VALIDITY_MS) {
    return state.nonce;
  }
  return undefined;
}

/**
 * Clear the DPoP state (for logout)
 */
export function clearDPoPState(): void {
  state.keyPair = null;
  state.nonce = null;
  state.lastNonceTime = 0;
}

/**
 * Fetch options for DPoP-protected requests
 */
export interface DPoPFetchOptions {
  /**
   * The access token to use
   */
  accessToken: string;
  /**
   * Optional DPoP key pair (defaults to stored)
   */
  keyPair?: DPoPKeyPair;
  /**
   * Optional nonce override
   */
  nonce?: string;
  /**
   * Include ATH claim (access token hash)
   */
  includeAth?: boolean;
  /**
   * Maximum number of retries on nonce errors
   */
  maxRetries?: number;
  /**
   * Request method
   */
  method?: string;
  /**
   * Request body
   */
  body?: BodyInit | null;
  /**
   * Request headers
   */
  headers?: HeadersInit;
  /**
   * Request mode
   */
  mode?: RequestMode;
  /**
   * Request credentials
   */
  credentials?: RequestCredentials;
  /**
   * Request cache
   */
  cache?: RequestCache;
  /**
   * Request redirect
   */
  redirect?: RequestRedirect;
  /**
   * Request referrer
   */
  referrer?: string;
  /**
   * Request integrity
   */
  integrity?: string;
  /**
   * Request keepalive
   */
  keepalive?: boolean;
  /**
   * Request signal
   */
  signal?: AbortSignal | null;
}

/**
 * Make a DPoP-protected fetch request
 *
 * @param url - The URL to fetch
 * @param options - DPoP fetch options
 * @returns Fetch response
 *
 * @example
 * ```ts
 * const response = await dpopFetch('https://api.example.com/users', {
 *   accessToken: session.access_token,
 *   method: 'GET',
 * });
 * ```
 */
export async function dpopFetch(
  url: string,
  options: DPoPFetchOptions
): Promise<Response> {
  const {
    accessToken,
    keyPair: providedKeyPair,
    nonce: providedNonce,
    includeAth = true,
    maxRetries = 2,
    ...fetchOptions
  } = options;

  const keyPair = providedKeyPair || await getOrCreateDPoPKeyPair();
  const method = fetchOptions.method || 'GET';
  const nonce = providedNonce || getDPoPNonce();

  // Import DPoP functions
  const { generateDPoPProof, hashAccessToken } = await import('./dpop');

  // Calculate ATH if requested
  let ath: string | undefined;
  if (includeAth) {
    ath = await hashAccessToken(accessToken);
  }

  // Generate DPoP proof
  const proof = await generateDPoPProof(keyPair, {
    htu: url,
    htm: method,
    dpopNonce: nonce,
    ath,
  });

  // Make the request
  const response = await fetch(url, {
    ...fetchOptions,
    headers: {
      ...fetchOptions.headers,
      'Authorization': `Bearer ${accessToken}`,
      'DPoP': proof,
    },
  });

  // Extract and store nonce from response
  const responseNonce = response.headers.get('dpop-nonce');
  if (responseNonce) {
    updateDPoPNonce(responseNonce);
  }

  // Handle 401 with use_dpop_nonce error - retry with new nonce
  if (
    response.status === 401 &&
    maxRetries > 0 &&
    responseNonce &&
    response.headers.get('content-type')?.includes('application/json')
  ) {
    try {
      const errorData = await response.clone().json();
      if (errorData.error === 'use_dpop_nonce' || errorData.error === 'invalid_dpop_proof') {
        // Retry with the new nonce
        return dpopFetch(url, {
          ...options,
          nonce: responseNonce,
          maxRetries: maxRetries - 1,
        });
      }
    } catch {
      // Ignore JSON parse errors
    }
  }

  return response;
}

/**
 * DPoP-aware fetch wrapper for general use
 *
 * Handles both regular and DPoP-protected requests.
 *
 * @param url - The URL to fetch
 * @param options - Request options
 * @param accessToken - Optional access token
 * @returns Fetch response
 */
export async function fetchWithDPoP(
  url: string,
  options: RequestInit = {},
  accessToken?: string
): Promise<Response> {
  if (!accessToken) {
    // No access token, make regular request
    return fetch(url, options);
  }

  // Use DPoP if we have an access token
  return dpopFetch(url, {
    ...options,
    accessToken,
  });
}
