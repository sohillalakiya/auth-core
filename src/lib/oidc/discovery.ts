/**
 * OIDC Provider Discovery Implementation
 *
 * Implements OpenID Connect Discovery 1.0 for dynamically fetching
 * provider configuration from the .well-known/openid-configuration endpoint.
 *
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html
 */

import { getConfig } from './env';
import type { OpenIDProviderMetadata } from './types';
import { DISCOVERY_PATH, PROVIDER_METADATA_CACHE_TTL } from './constants';

/**
 * Cached provider metadata with expiration timestamp
 */
interface CachedMetadata {
  metadata: OpenIDProviderMetadata;
  expiresAt: number;
}

/**
 * In-memory cache for provider metadata
 * In a multi-instance deployment, this should be replaced with a distributed cache
 */
const metadataCache: Map<string, CachedMetadata> = new Map();

/**
 * Constructs the discovery URL for a given issuer.
 *
 * @param issuer - The OIDC provider issuer URL
 * @returns The full discovery URL
 *
 * @example
 * ```ts
 * const discoveryUrl = getDiscoveryUrl('https://accounts.google.com');
 * // Returns: 'https://accounts.google.com/.well-known/openid-configuration'
 * ```
 */
export function getDiscoveryUrl(issuer: string): string {
  // Remove trailing slash if present
  const normalizedIssuer = issuer.replace(/\/$/, '');
  return `${normalizedIssuer}${DISCOVERY_PATH}`;
}

/**
 * Fetches the OpenID Provider configuration from the discovery endpoint.
 *
 * @param issuer - The OIDC provider issuer URL
 * @param cacheBust - If true, bypasses the cache and forces a fresh fetch
 * @returns The provider's metadata
 * @throws {DiscoveryError} If fetching or parsing fails
 *
 * @example
 * ```ts
 * const metadata = await fetchProviderMetadata('https://accounts.google.com');
 * console.log(metadata.authorization_endpoint);
 * ```
 */
export async function fetchProviderMetadata(
  issuer: string,
  cacheBust: boolean = false
): Promise<OpenIDProviderMetadata> {
  // Check cache first (unless bypassing)
  if (!cacheBust) {
    const cached = metadataCache.get(issuer);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.metadata;
    }
  }

  const discoveryUrl = getDiscoveryUrl(issuer);

  try {
    const response = await fetch(discoveryUrl, {
      headers: {
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(10000), // 10 second timeout
    });

    if (!response.ok) {
      throw new Error(
        `Failed to fetch provider metadata: ${response.status} ${response.statusText}`
      );
    }

    const contentType = response.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
      throw new Error(
        `Invalid content type from discovery endpoint: ${contentType}`
      );
    }

    const metadata: OpenIDProviderMetadata = await response.json();

    // Validate the metadata
    validateProviderMetadata(metadata, issuer);

    // Cache the metadata
    metadataCache.set(issuer, {
      metadata,
      expiresAt: Date.now() + PROVIDER_METADATA_CACHE_TTL,
    });

    return metadata;
  } catch (error) {
    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        throw new Error(
          `Timeout while fetching provider metadata from ${discoveryUrl}`
        );
      }
      throw error;
    }
    throw new Error(
      `Unknown error while fetching provider metadata from ${discoveryUrl}`
    );
  }
}

/**
 * Validates the OpenID Provider Metadata.
 *
 * Ensures all required fields are present and valid according to the
 * OpenID Connect Discovery specification.
 *
 * REQUIRED fields:
 * - issuer
 * - authorization_endpoint
 * - token_endpoint
 * - jwks_uri
 * - userinfo_endpoint
 * - end_session_endpoint
 * - introspection_endpoint
 * - response_types_supported (must include 'code')
 * - subject_types_supported
 * - id_token_signing_alg_values_supported
 * - code_challenge_methods_supported (must include 'S256')
 *
 * @param metadata - The provider metadata to validate
 * @param expectedIssuer - The expected issuer URL (for validation)
 * @throws {Error} If validation fails
 *
 * @example
 * ```ts
 * validateProviderMetadata(metadata, 'https://accounts.google.com');
 * ```
 */
export function validateProviderMetadata(
  metadata: OpenIDProviderMetadata,
  expectedIssuer?: string
): void {
  const errors: string[] = [];

  // Required fields per OpenID Connect Discovery 1.0
  const requiredFields = [
    'issuer',
    'authorization_endpoint',
    'token_endpoint',
    'jwks_uri',
    'response_types_supported',
    'subject_types_supported',
    'id_token_signing_alg_values_supported',
  ] as const;

  for (const field of requiredFields) {
    if (!metadata[field]) {
      errors.push(`Missing required field: ${field}`);
    }
  }

  // REQUIRED: userinfo_endpoint
  if (!metadata.userinfo_endpoint) {
    errors.push('Missing required field: userinfo_endpoint');
  }

  // REQUIRED: end_session_endpoint (for RP-Initiated Logout)
  if (!metadata.end_session_endpoint) {
    errors.push('Missing required field: end_session_endpoint');
  }

  // REQUIRED: introspection_endpoint (for token validation)
  if (!metadata.introspection_endpoint) {
    errors.push('Missing required field: introspection_endpoint');
  }

  // Validate issuer matches expected issuer (if provided)
  if (expectedIssuer && metadata.issuer) {
    const normalizedExpected = expectedIssuer.replace(/\/$/, '');
    const normalizedIssuer = metadata.issuer.replace(/\/$/, '');
    if (normalizedIssuer !== normalizedExpected) {
      errors.push(
        `Issuer mismatch: expected "${normalizedExpected}", got "${normalizedIssuer}"`
      );
    }
  }

  // Validate URLs are properly formatted
  const urlFields: (keyof OpenIDProviderMetadata)[] = [
    'authorization_endpoint',
    'token_endpoint',
    'jwks_uri',
    'userinfo_endpoint',
    'end_session_endpoint',
    'introspection_endpoint',
  ];

  for (const field of urlFields) {
    const value = metadata[field];
    if (value && typeof value === 'string') {
      try {
        new URL(value);
      } catch {
        errors.push(`${field} is not a valid URL`);
      }
    }
  }

  // Validate response_types_supported includes 'code' (required for Authorization Code Flow)
  if (
    metadata.response_types_supported &&
    !metadata.response_types_supported.includes('code')
  ) {
    errors.push(
      'Provider does not support "code" response type (required for Authorization Code Flow)'
    );
  }

  // Validate at least one signing algorithm is supported
  if (
    metadata.id_token_signing_alg_values_supported &&
    metadata.id_token_signing_alg_values_supported.length === 0
  ) {
    errors.push('No ID token signing algorithms supported');
  }

  // Check for 'none' algorithm (security risk)
  if (
    metadata.id_token_signing_alg_values_supported?.includes('none') &&
    metadata.id_token_signing_alg_values_supported.length === 1
  ) {
    errors.push(
      'Provider only supports "none" signing algorithm, which is not secure'
    );
  }

  // REQUIRED: PKCE support - code_challenge_methods_supported must be present and include 'S256'
  if (!metadata.code_challenge_methods_supported) {
    errors.push(
      'Missing required field: code_challenge_methods_supported (PKCE is mandatory)'
    );
  } else if (!metadata.code_challenge_methods_supported.includes('S256')) {
    errors.push(
      'Provider does not support "S256" code challenge method (PKCE is mandatory)'
    );
  }

  if (errors.length > 0) {
    throw new Error(
      `Invalid provider metadata:\n${errors.map((e) => `  - ${e}`).join('\n')}`
    );
  }
}

/**
 * Validates that the provider supports PKCE with S256 method.
 *
 * PKCE is mandatory for this implementation.
 *
 * @param metadata - The provider metadata
 * @returns true if PKCE S256 is supported
 * @throws {Error} If PKCE S256 is not supported
 *
 * @example
 * ```ts
 * const metadata = await fetchProviderMetadata(issuer);
 * assertSupportsPKCE(metadata); // Throws if not supported
 * ```
 */
export function assertSupportsPKCE(metadata: OpenIDProviderMetadata): boolean {
  if (!metadata.code_challenge_methods_supported) {
    throw new Error(
      'Provider does not advertise code_challenge_methods_supported (PKCE is mandatory)'
    );
  }

  if (!metadata.code_challenge_methods_supported.includes('S256')) {
    throw new Error(
      'Provider does not support S256 code challenge method (PKCE is mandatory)'
    );
  }

  return true;
}

/**
 * Checks if the provider supports PKCE.
 *
 * @param metadata - The provider metadata
 * @returns true if PKCE S256 is supported, false otherwise
 *
 * @example
 * ```ts
 * const metadata = await fetchProviderMetadata(issuer);
 * if (!supportsPKCE(metadata)) {
 *   throw new Error('Provider does not support PKCE');
 * }
 * ```
 */
export function supportsPKCE(metadata: OpenIDProviderMetadata): boolean {
  if (!metadata.code_challenge_methods_supported) {
    return false;
  }
  return metadata.code_challenge_methods_supported.includes('S256');
}

/**
 * Validates that the provider supports the required scopes.
 *
 * @param metadata - The provider metadata
 * @param scopes - Array of required scopes
 * @returns true if all scopes are supported, false otherwise
 *
 * @example
 * ```ts
 * const metadata = await fetchProviderMetadata(issuer);
 * const requiredScopes = ['openid', 'profile', 'email'];
 * if (!supportsScopes(metadata, requiredScopes)) {
 *   console.warn('Provider does not support all requested scopes');
 * }
 * ```
 */
export function supportsScopes(
  metadata: OpenIDProviderMetadata,
  scopes: string[]
): boolean {
  if (!metadata.scopes_supported || metadata.scopes_supported.length === 0) {
    // If not advertised, assume standard scopes are supported
    return true;
  }

  // Check each requested scope
  for (const scope of scopes) {
    // Handle space-separated scope strings
    const scopeParts = scope.split(/\s+/);
    for (const part of scopeParts) {
      if (!metadata.scopes_supported!.includes(part)) {
        // Check for pattern scopes (e.g., "read:blah")
        // Some providers use wildcards or patterns
        const hasPatternSupport = metadata.scopes_supported!.some((supported) =>
          supported.includes('*')
        );
        if (!hasPatternSupport) {
          return false;
        }
      }
    }
  }

  return true;
}

/**
 * Validates that the provider supports the required response type.
 *
 * @param metadata - The provider metadata
 * @param responseType - The response type (e.g., 'code', 'id_token')
 * @returns true if the response type is supported, false otherwise
 *
 * @example
 * ```ts
 * const metadata = await fetchProviderMetadata(issuer);
 * if (!supportsResponseType(metadata, 'code')) {
 *   throw new Error('Provider does not support authorization code flow');
 * }
 * ```
 */
export function supportsResponseType(
  metadata: OpenIDProviderMetadata,
  responseType: string
): boolean {
  return (
    metadata.response_types_supported?.includes(responseType) ?? false
  );
}

/**
 * Clears the cached provider metadata for a given issuer.
 *
 * @param issuer - The issuer URL to clear from cache
 *
 * @example
 * ```ts
 * clearProviderMetadataCache('https://accounts.google.com');
 * ```
 */
export function clearProviderMetadataCache(issuer: string): void {
  metadataCache.delete(issuer);
}

/**
 * Clears all cached provider metadata.
 *
 * @example
 * ```ts
 * clearAllProviderMetadataCache();
 * ```
 */
export function clearAllProviderMetadataCache(): void {
  metadataCache.clear();
}

/**
 * Gets the provider's JWKS URL.
 *
 * @param metadata - The provider metadata
 * @returns The JWKS URL
 *
 * @example
 * ```ts
 * const metadata = await fetchProviderMetadata(issuer);
 * const jwksUrl = getJwksUrl(metadata);
 * ```
 */
export function getJwksUrl(metadata: OpenIDProviderMetadata): string {
  return metadata.jwks_uri;
}

/**
 * Gets the provider's authorization endpoint URL.
 *
 * @param metadata - The provider metadata
 * @returns The authorization endpoint URL
 */
export function getAuthorizationEndpoint(
  metadata: OpenIDProviderMetadata
): string {
  return metadata.authorization_endpoint;
}

/**
 * Gets the provider's token endpoint URL.
 *
 * @param metadata - The provider metadata
 * @returns The token endpoint URL
 */
export function getTokenEndpoint(metadata: OpenIDProviderMetadata): string {
  return metadata.token_endpoint;
}

/**
 * Gets the provider's UserInfo endpoint URL.
 *
 * @param metadata - The provider metadata
 * @returns The UserInfo endpoint URL
 * @throws {Error} If userinfo_endpoint is not available
 */
export function getUserInfoEndpoint(
  metadata: OpenIDProviderMetadata
): string {
  if (!metadata.userinfo_endpoint) {
    throw new Error('Provider does not provide a UserInfo endpoint');
  }
  return metadata.userinfo_endpoint;
}

/**
 * Gets the provider's end session endpoint URL.
 *
 * @param metadata - The provider metadata
 * @returns The end session endpoint URL
 * @throws {Error} If end_session_endpoint is not available
 */
export function getEndSessionEndpoint(
  metadata: OpenIDProviderMetadata
): string {
  if (!metadata.end_session_endpoint) {
    throw new Error('Provider does not provide an end session endpoint');
  }
  return metadata.end_session_endpoint;
}

/**
 * Gets the provider's introspection endpoint URL.
 *
 * @param metadata - The provider metadata
 * @returns The introspection endpoint URL
 * @throws {Error} If introspection_endpoint is not available
 */
export function getIntrospectionEndpoint(
  metadata: OpenIDProviderMetadata
): string {
  if (!metadata.introspection_endpoint) {
    throw new Error('Provider does not provide an introspection endpoint');
  }
  return metadata.introspection_endpoint;
}

/**
 * Discovers the provider configuration using the configured issuer.
 *
 * Convenience function that uses the issuer from environment config.
 *
 * @param cacheBust - If true, bypasses the cache
 * @returns The provider's metadata
 *
 * @example
 * ```ts
 * const metadata = await discoverProvider();
 * ```
 */
export async function discoverProvider(
  cacheBust: boolean = false
): Promise<OpenIDProviderMetadata> {
  const config = getConfig();
  return fetchProviderMetadata(config.issuer, cacheBust);
}
