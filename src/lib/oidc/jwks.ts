/**
 * JWKS (JSON Web Key Set) Implementation
 *
 * Handles fetching and caching of public keys for JWT signature verification.
 * Supports key rotation and key ID (kid) matching.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7517
 */

import type { JWKS, JWK } from './types';
import { JWKS_CACHE_TTL } from './constants';

/**
 * Cached JWKS with expiration timestamp
 */
interface CachedJWKS {
  jwks: JWKS;
  expiresAt: number;
}

/**
 * In-memory cache for JWKS
 * In a multi-instance deployment, this should be replaced with a distributed cache
 */
let jwksCache: Map<string, CachedJWKS> = new Map();

/**
 * Fetches the JWKS from the given URL.
 *
 * @param jwksUri - The JWKS endpoint URL
 * @param cacheBust - If true, bypasses the cache and forces a fresh fetch
 * @returns The JSON Web Key Set
 * @throws {Error} If fetching or parsing fails
 *
 * @example
 * ```ts
 * const jwks = await fetchJWKS('https://example.com/.well-known/jwks.json');
 * ```
 */
export async function fetchJWKS(
  jwksUri: string,
  cacheBust: boolean = false
): Promise<JWKS> {
  // Check cache first (unless bypassing)
  if (!cacheBust) {
    const cached = jwksCache.get(jwksUri);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.jwks;
    }
  }

  try {
    const response = await fetch(jwksUri, {
      headers: {
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(10000), // 10 second timeout
    });

    if (!response.ok) {
      throw new Error(
        `Failed to fetch JWKS: ${response.status} ${response.statusText}`
      );
    }

    const contentType = response.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
      throw new Error(
        `Invalid content type from JWKS endpoint: ${contentType}`
      );
    }

    const jwks: JWKS = await response.json();

    // Validate JWKS structure
    if (!jwks.keys || !Array.isArray(jwks.keys)) {
      throw new Error('Invalid JWKS: missing or invalid "keys" array');
    }

    // Cache the JWKS
    jwksCache.set(jwksUri, {
      jwks,
      expiresAt: Date.now() + JWKS_CACHE_TTL,
    });

    return jwks;
  } catch (error) {
    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        throw new Error(
          `Timeout while fetching JWKS from ${jwksUri}`
        );
      }
      throw error;
    }
    throw new Error(
      `Unknown error while fetching JWKS from ${jwksUri}`
    );
  }
}

/**
 * Finds a key in the JWKS by its Key ID (kid).
 *
 * @param jwks - The JSON Web Key Set to search
 * @param kid - The Key ID to find
 * @returns The matching JWK, or undefined if not found
 *
 * @example
 * ```ts
 * const jwks = await fetchJWKS(jwksUri);
 * const key = findKeyById(jwks, 'key-123');
 * if (key) {
 *   console.log('Found key:', key);
 * }
 * ```
 */
export function findKeyById(jwks: JWKS, kid: string): JWK | undefined {
  return jwks.keys.find((key) => key.kid === kid);
}

/**
 * Finds a key in the JWKS by Key ID (kid) and algorithm (alg).
 *
 * @param jwks - The JSON Web Key Set to search
 * @param kid - The Key ID to find
 * @param alg - The algorithm to match
 * @returns The matching JWK, or undefined if not found
 *
 * @example
 * ```ts
 * const jwks = await fetchJWKS(jwksUri);
 * const key = findKeyByIdAndAlg(jwks, 'key-123', 'RS256');
 * if (key) {
 *   console.log('Found RS256 key:', key);
 * }
 * ```
 */
export function findKeyByIdAndAlg(
  jwks: JWKS,
  kid: string,
  alg: string
): JWK | undefined {
  return jwks.keys.find(
    (key) => key.kid === kid && key.alg === alg
  );
}

/**
 * Finds keys in the JWKS by Key Type (kty).
 *
 * @param jwks - The JSON Web Key Set to search
 * @param kty - The Key Type (e.g., 'RSA', 'EC')
 * @returns Array of matching JWKs
 *
 * @example
 * ```ts
 * const jwks = await fetchJWKS(jwksUri);
 * const rsaKeys = findKeysByType(jwks, 'RSA');
 * console.log(`Found ${rsaKeys.length} RSA keys`);
 * ```
 */
export function findKeysByType(jwks: JWKS, kty: string): JWK[] {
  return jwks.keys.filter((key) => key.kty === kty);
}

/**
 * Finds keys in the JWKS by their public key use (use).
 *
 * @param jwks - The JSON Web Key Set to search
 * @param use - The use type (e.g., 'sig' for signature, 'enc' for encryption)
 * @returns Array of matching JWKs
 *
 * @example
 * ```ts
 * const jwks = await fetchJWKS(jwksUri);
 * const sigKeys = findKeysByUse(jwks, 'sig');
 * console.log(`Found ${sigKeys.length} signature keys`);
 * ```
 */
export function findKeysByUse(jwks: JWKS, use: string): JWK[] {
  return jwks.keys.filter((key) => key.use === use);
}

/**
 * Gets a key from the JWKS by kid, throwing an error if not found.
 *
 * @param jwks - The JSON Web Key Set to search
 * @param kid - The Key ID to find
 * @returns The matching JWK
 * @throws {Error} If the key is not found
 *
 * @example
 * ```ts
 * const jwks = await fetchJWKS(jwksUri);
 * try {
 *   const key = getKeyById(jwks, 'key-123');
 *   // Use the key
 * } catch (error) {
 *   console.error('Key not found');
 * }
 * ```
 */
export function getKeyById(jwks: JWKS, kid: string): JWK {
  const key = findKeyById(jwks, kid);
  if (!key) {
    throw new Error(
      `No key found with kid "${kid}" in JWKS`
    );
  }
  return key;
}

/**
 * Validates that a JWK contains the required parameters for its key type.
 *
 * For RSA keys: requires n (modulus) and e (exponent)
 * For EC keys: requires x and y coordinates
 *
 * @param jwk - The JWK to validate
 * @returns true if the JWK is valid, false otherwise
 *
 * @example
 * ```ts
 * const jwk = getKeyById(jwks, 'key-123');
 * if (!isValidJWK(jwk)) {
 *   throw new Error('Invalid key');
 * }
 * ```
 */
export function isValidJWK(jwk: JWK): boolean {
  // All keys must have a key type
  if (!jwk.kty) {
    return false;
  }

  switch (jwk.kty) {
    case 'RSA':
      // RSA keys require modulus and exponent
      return !!(jwk.n && jwk.e);

    case 'EC':
      // EC keys require x and y coordinates
      return !!(jwk.x && jwk.y);

    case 'oct':
      // Symmetric keys require the key value
      return !!jwk.k;

    default:
      // Unknown key types are considered invalid
      return false;
  }
}

/**
 * Filters valid JWKs from a JWKS.
 *
 * @param jwks - The JSON Web Key Set
 * @returns Array of valid JWKs
 *
 * @example
 * ```ts
 * const jwks = await fetchJWKS(jwksUri);
 * const validKeys = getValidKeys(jwks);
 * console.log(`Found ${validKeys.length} valid keys`);
 * ```
 */
export function getValidKeys(jwks: JWKS): JWK[] {
  return jwks.keys.filter(isValidJWK);
}

/**
 * Clears the cached JWKS for a given URI.
 *
 * @param jwksUri - The JWKS URI to clear from cache
 *
 * @example
 * ```ts
 * clearJWKSCache('https://example.com/.well-known/jwks.json');
 * ```
 */
export function clearJWKSCache(jwksUri: string): void {
  jwksCache.delete(jwksUri);
}

/**
 * Clears all cached JWKS.
 *
 * @example
 * ```ts
 * clearAllJWKSCache();
 * ```
 */
export function clearAllJWKSCache(): void {
  jwksCache.clear();
}

/**
 * Gets the cache entry for a JWKS URI (including expiration info).
 *
 * @param jwksUri - The JWKS URI
 * @returns The cached entry or undefined if not cached
 *
 * @example
 * ```ts
 * const cached = getJWKSCacheEntry(jwksUri);
 * if (cached) {
 *   console.log('Expires at:', new Date(cached.expiresAt));
 * }
 * ```
 */
export function getJWKSCacheEntry(
  jwksUri: string
): { jwks: JWKS; expiresAt: number } | undefined {
  const cached = jwksCache.get(jwksUri);
  if (cached && cached.expiresAt > Date.now()) {
    return cached;
  }
  return undefined;
}

/**
 * Returns the number of keys in a JWKS.
 *
 * @param jwks - The JSON Web Key Set
 * @returns The number of keys
 *
 * @example
 * ```ts
 * const jwks = await fetchJWKS(jwksUri);
 * console.log(`Provider has ${getKeyCount(jwks)} keys`);
 * ```
 */
export function getKeyCount(jwks: JWKS): number {
  return jwks.keys.length;
}

/**
 * Returns statistics about a JWKS.
 *
 * @param jwks - The JSON Web Key Set
 * @returns Statistics object with key counts by type
 *
 * @example
 * ```ts
 * const jwks = await fetchJWKS(jwksUri);
 * const stats = getJWKSStats(jwks);
 * console.log('RSA keys:', stats.rsa);
 * console.log('EC keys:', stats.ec);
 * console.log('Total:', stats.total);
 * ```
 */
export function getJWKSStats(jwks: JWKS): {
  total: number;
  rsa: number;
  ec: number;
  oct: number;
  other: number;
  withKid: number;
  withoutKid: number;
} {
  const stats = {
    total: jwks.keys.length,
    rsa: 0,
    ec: 0,
    oct: 0,
    other: 0,
    withKid: 0,
    withoutKid: 0,
  };

  for (const key of jwks.keys) {
    // Count by key type
    switch (key.kty) {
      case 'RSA':
        stats.rsa++;
        break;
      case 'EC':
        stats.ec++;
        break;
      case 'oct':
        stats.oct++;
        break;
      default:
        stats.other++;
    }

    // Count by kid presence
    if (key.kid) {
      stats.withKid++;
    } else {
      stats.withoutKid++;
    }
  }

  return stats;
}
