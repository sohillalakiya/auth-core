/**
 * OIDC ID Token Validation
 *
 * Validates ID tokens per OpenID Connect Core 1.0 specification and RFC 7519.
 * Implements JWT signature verification, claims validation, and nonce checking.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
 * @see https://www.rfc-editor.org/rfc/rfc7519
 */

import { createVerify, createPublicKey } from 'crypto';
import { getConfig } from './env';
import { discoverProvider } from './discovery';
import { fetchJWKS, findKeyById } from './jwks';
import type { IDTokenClaims, JWTHeader, JWKS } from './types';
import { JWT_CONSTANTS, TIME_CONSTANTS } from './constants';

/**
 * Result of ID token validation
 */
export interface IDTokenValidationResult {
  /** Whether the token is valid */
  valid: boolean;
  /** The validated claims */
  claims?: IDTokenClaims;
  /** Error details if validation failed */
  error?: string;
  /** Error code for categorization */
  errorCode?: string;
}

/**
 * Options for ID token validation
 */
export interface IDTokenValidationOptions {
  /** The ID token to validate */
  idToken: string;
  /** The nonce to validate (from auth state) */
  nonce?: string;
  /** The expected issuer (defaults to config) */
  issuer?: string;
  /** The expected audience (defaults to client_id) */
  audience?: string;
  /** Maximum allowed token age in seconds */
  maxAge?: number;
  /** Clock skew tolerance in seconds */
  clockSkew?: number;
}

/**
 * Decodes a JWT header without verifying the signature.
 *
 * @param jwt - The JWT string
 * @returns The decoded header
 * @throws {Error} If the JWT format is invalid
 *
 * @example
 * ```ts
 * const header = decodeJWTHeader('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...');
 * console.log(header.alg); // 'RS256'
 * ```
 */
export function decodeJWTHeader(jwt: string): JWTHeader {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format: expected 3 parts (header.payload.signature)');
  }

  try {
    const header = parts[0];
    const base64 = header.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
    const decoded = Buffer.from(padded, 'base64').toString('utf-8');
    return JSON.parse(decoded) as JWTHeader;
  } catch {
    throw new Error('Failed to decode JWT header');
  }
}

/**
 * Decodes a JWT payload without verifying the signature.
 *
 * @param jwt - The JWT string
 * @returns The decoded payload
 * @throws {Error} If the JWT format is invalid
 *
 * @example
 * ```ts
 * const payload = decodeJWTPayload('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...');
 * console.log(payload.sub); // 'user-id'
 * ```
 */
export function decodeJWTPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format: expected 3 parts (header.payload.signature)');
  }

  try {
    const payload = parts[1];
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
    const decoded = Buffer.from(padded, 'base64').toString('utf-8');
    return JSON.parse(decoded);
  } catch {
    throw new Error('Failed to decode JWT payload');
  }
}

/**
 * Decodes a JWT into its three parts.
 *
 * @param jwt - The JWT string
 * @returns Object containing header, payload, and signature
 *
 * @example
 * ```ts
 * const { header, payload, signature } = decodeJWT(token);
 * ```
 */
export function decodeJWT(jwt: string): {
  header: JWTHeader;
  payload: Record<string, unknown>;
  signature: string;
} {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format: expected 3 parts (header.payload.signature)');
  }

  return {
    header: decodeJWTHeader(jwt),
    payload: decodeJWTPayload(jwt),
    signature: parts[2],
  };
}

/**
 * Validates the JWT header.
 *
 * Checks for:
 * - Algorithm is present and supported
 * - 'none' algorithm is rejected
 *
 * @param header - The JWT header to validate
 * @param supportedAlgorithms - Array of supported algorithms (from provider metadata)
 * @throws {Error} If validation fails
 */
export function validateJWTHeader(
  header: JWTHeader,
  supportedAlgorithms?: string[]
): void {
  if (!header.alg) {
    throw new Error('JWT header missing "alg" (algorithm) claim');
  }

  // Reject 'none' algorithm (no signature)
  if (header.alg === 'none') {
    throw new Error('JWT algorithm "none" is not allowed for security reasons');
  }

  // Check against provider's supported algorithms if available
  if (supportedAlgorithms && supportedAlgorithms.length > 0) {
    if (!supportedAlgorithms.includes(header.alg)) {
      throw new Error(
        `JWT algorithm "${header.alg}" is not in provider's supported algorithms: ${supportedAlgorithms.join(', ')}`
      );
    }
  }

  // Check against our list of supported algorithms
  if (!JWT_CONSTANTS.SUPPORTED_ALGORITHMS.includes(header.alg as typeof JWT_CONSTANTS.SUPPORTED_ALGORITHMS[number])) {
    throw new Error(
      `JWT algorithm "${header.alg}" is not supported. Supported algorithms: ${JWT_CONSTANTS.SUPPORTED_ALGORITHMS.join(', ')}`
    );
  }
}

/**
 * Validates the required claims in an ID token.
 *
 * Per OpenID Connect Core 1.0, the following claims are REQUIRED:
 * - iss (issuer)
 * - sub (subject)
 * - aud (audience)
 * - exp (expiration)
 * - iat (issued at)
 *
 * @param claims - The ID token claims to validate
 * @throws {Error} If validation fails
 */
export function validateRequiredClaims(claims: IDTokenClaims): void {
  const errors: string[] = [];

  for (const claim of JWT_CONSTANTS.REQUIRED_CLAIMS) {
    if (claims[claim as keyof IDTokenClaims] === undefined) {
      errors.push(`Missing required claim: ${claim}`);
    }
  }

  if (errors.length > 0) {
    throw new Error(`ID token validation failed:\n${errors.map((e) => `  - ${e}`).join('\n')}`);
  }
}

/**
 * Validates the issuer (iss) claim.
 *
 * @param issuer - The issuer claim from the ID token
 * @param expectedIssuer - The expected issuer URL
 * @throws {Error} If the issuer doesn't match
 */
export function validateIssuer(issuer: string, expectedIssuer: string): void {
  // Normalize both issuers (remove trailing slashes)
  const normalizedIss = issuer.replace(/\/$/, '');
  const normalizedExpected = expectedIssuer.replace(/\/$/, '');

  if (normalizedIss !== normalizedExpected) {
    throw new Error(
      `ID token issuer mismatch: expected "${normalizedExpected}", got "${normalizedIss}"`
    );
  }
}

/**
 * Validates the audience (aud) claim.
 *
 * The aud claim MUST contain the client_id. If aud contains multiple
 * values, one of them must be the client_id.
 *
 * @param audience - The audience claim from the ID token (string or array)
 * @param clientId - The expected client ID
 * @throws {Error} If the audience doesn't contain the client_id
 */
export function validateAudience(
  audience: string | string[],
  clientId: string
): void {
  const audiences = Array.isArray(audience) ? audience : [audience];

  if (!audiences.includes(clientId)) {
    throw new Error(
      `ID token audience does not include client_id "${clientId}". Audiences: ${audiences.join(', ')}`
    );
  }
}

/**
 * Validates the expiration (exp) claim.
 *
 * @param expiration - The expiration timestamp (seconds since epoch)
 * @param clockSkew - Clock skew tolerance in seconds (default: 60)
 * @throws {Error} If the token is expired
 */
export function validateExpiration(expiration: number, clockSkew: number = TIME_CONSTANTS.CLOCK_SKEW_TOLERANCE): void {
  const now = Math.floor(Date.now() / 1000);
  const adjustedExpiry = expiration + clockSkew;

  if (now > adjustedExpiry) {
    throw new Error(
      `ID token expired at ${new Date(expiration * 1000).toISOString()} (current time: ${new Date(now * 1000).toISOString()})`
    );
  }
}

/**
 * Validates the issued at (iat) claim.
 *
 * Ensures the token wasn't issued in the future (accounting for clock skew).
 *
 * @param issuedAt - The issued at timestamp (seconds since epoch)
 * @param clockSkew - Clock skew tolerance in seconds (default: 60)
 * @throws {Error} If the token was issued in the future
 */
export function validateIssuedAt(issuedAt: number, clockSkew: number = TIME_CONSTANTS.CLOCK_SKEW_TOLERANCE): void {
  const now = Math.floor(Date.now() / 1000);
  const adjustedFuture = now + clockSkew;

  if (issuedAt > adjustedFuture) {
    throw new Error(
      `ID token issued at time ${new Date(issuedAt * 1000).toISOString()} is in the future (current time: ${new Date(now * 1000).toISOString()})`
    );
  }
}

/**
 * Validates the nonce (nonce) claim.
 *
 * The nonce claim must match the nonce sent in the authorization request.
 * This prevents replay attacks.
 *
 * @param nonce - The nonce claim from the ID token
 * @param expectedNonce - The expected nonce from auth state
 * @throws {Error} If the nonce doesn't match
 */
export function validateNonce(nonce: string, expectedNonce: string): void {
  if (nonce !== expectedNonce) {
    throw new Error(
      'ID token nonce mismatch. This may indicate a replay attack or tampered authentication request.'
    );
  }
}

/**
 * Validates the authentication time (auth_time) claim against max_age.
 *
 * @param authTime - The authentication time from the ID token
 * @param maxAge - Maximum allowed authentication age in seconds
 * @throws {Error} If the authentication is too old
 */
export function validateAuthTime(authTime: number, maxAge: number): void {
  const now = Math.floor(Date.now() / 1000);
  const authAge = now - authTime;

  if (authAge > maxAge) {
    throw new Error(
      `Authentication time ${authAge} seconds ago exceeds max_age of ${maxAge} seconds`
    );
  }
}

/**
 * Validates the authorized party (azp) claim.
 *
 * If azp is present, it must match the client_id when aud contains multiple values.
 *
 * @param azp - The authorized party claim
 * @param clientId - The client ID
 * @param audience - The audience claim
 * @throws {Error} If validation fails
 */
export function validateAuthorizedParty(
  azp: string,
  clientId: string,
  audience: string | string[]
): void {
  const audiences = Array.isArray(audience) ? audience : [audience];

  // azp must equal client_id if there are multiple audiences
  if (audiences.length > 1 && azp !== clientId) {
    throw new Error(
      `ID token azp "${azp}" must equal client_id "${clientId}" when multiple audiences are present`
    );
  }
}

/**
 * Converts a JWK to a PEM public key.
 *
 * @param jwk - The JSON Web Key
 * @returns The PEM-formatted public key
 * @throws {Error} If conversion fails
 */
export function jwkToPem(jwk: { kty: string; n?: string; e?: string; x?: string; y?: string; crv?: string }): string {
  if (jwk.kty === 'RSA' && jwk.n && jwk.e) {
    // This is a simplified version - for production, use proper key formatting
    // For now, we'll use Node's crypto module which can handle base64url directly
    return `-----BEGIN RSA PUBLIC KEY-----
${Buffer.from(JSON.stringify({ n: jwk.n, e: jwk.e, kty: 'RSA' })).toString('base64')}
-----END RSA PUBLIC KEY-----`;
  } else if (jwk.kty === 'EC' && jwk.x && jwk.y && jwk.crv) {
    // EC key - more complex handling needed
    throw new Error('EC key conversion not yet implemented');
  }

  throw new Error(`Unsupported key type: ${jwk.kty}`);
}

/**
 * Verifies the JWT signature using the provider's JWKS.
 *
 * @param jwt - The JWT to verify
 * @param jwks - The JSON Web Key Set from the provider
 * @returns The verification result
 * @throws {Error} If verification fails
 */
export function verifyJWTSignature(jwt: string, jwks: JWKS): boolean {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  const { header, signature } = decodeJWT(jwt);
  const kid = header.kid;

  // Find the matching key by kid
  if (!kid) {
    throw new Error('JWT header missing "kid" (key ID) claim');
  }

  const key = findKeyById(jwks, kid);
  if (!key) {
    throw new Error(
      `No matching key found in JWKS for kid "${kid}"`
    );
  }

  // Validate the key structure
  if (key.kty !== 'RSA' || !key.n || !key.e) {
    throw new Error('Only RSA keys are currently supported for JWT verification');
  }

  // Verify the signature
  const message = `${parts[0]}.${parts[1]}`;
  const signatureBuffer = Buffer.from(signature, 'base64url');

  try {
    // Create a public key from the JWK
    // Node.js createPublicKey can handle JWK format directly in newer versions
    const publicKey = createPublicKey({
      key: {
        kty: key.kty,
        n: key.n,
        e: key.e,
      },
      format: 'jwk',
    });

    const verify = createVerify('SHA256');
    verify.update(message);
    verify.end();

    const isValid = verify.verify(publicKey, signatureBuffer);

    if (!isValid) {
      throw new Error('JWT signature verification failed');
    }

    return true;
  } catch (error) {
    if (error instanceof Error && error.message === 'JWT signature verification failed') {
      throw error;
    }
    throw new Error(
      `Failed to verify JWT signature: ${error instanceof Error ? error.message : 'Unknown error'}`
    );
  }
}

/**
 * Validates an ID token completely.
 *
 * This function performs all required ID token validations per OpenID Connect Core 1.0:
 * 1. JWT structure validation
 * 2. Header validation (algorithm)
 * 3. Signature verification using JWKS
 * 4. Required claims validation
 * 5. Issuer validation
 * 6. Audience validation
 * 7. Expiration validation
 * 8. Issued at validation
 * 9. Nonce validation (if provided)
 *
 * @param options - Validation options
 * @returns Validation result with claims if successful
 *
 * @example
 * ```ts
 * const result = await validateIDToken({
 *   idToken: tokens.id_token,
 *   nonce: authState.nonce,
 * });
 *
 * if (result.valid) {
 *   console.log('User ID:', result.claims.sub);
 * } else {
 *   console.error('Validation failed:', result.error);
 * }
 * ```
 */
export async function validateIDToken(
  options: IDTokenValidationOptions
): Promise<IDTokenValidationResult> {
  try {
    const { idToken, nonce, issuer, audience, maxAge, clockSkew } = options;

    // Get configuration
    const config = getConfig();
    const expectedIssuer = issuer || config.issuer;
    const expectedAudience = audience || config.clientId;

    // Decode JWT header
    const { header, payload } = decodeJWT(idToken);

    // Discover provider to get supported algorithms and JWKS
    const provider = await discoverProvider();
    validateJWTHeader(header, provider.id_token_signing_alg_values_supported);

    // Fetch JWKS and verify signature
    const jwksUri = provider.jwks_uri;
    const jwks = await fetchJWKS(jwksUri);
    verifyJWTSignature(idToken, jwks);

    // Parse claims
    const claims = payload as unknown as IDTokenClaims;

    // Validate required claims
    validateRequiredClaims(claims);

    // Validate issuer
    validateIssuer(claims.iss, expectedIssuer);

    // Validate audience
    validateAudience(claims.aud, expectedAudience);

    // Validate expiration
    validateExpiration(claims.exp, clockSkew);

    // Validate issued at
    validateIssuedAt(claims.iat, clockSkew);

    // Validate nonce if provided
    if (nonce) {
      if (!claims.nonce) {
        return {
          valid: false,
          error: 'ID token missing nonce claim',
          errorCode: 'nonce_missing',
        };
      }
      validateNonce(claims.nonce, nonce);
    }

    // Validate auth_time against max_age if provided
    if (maxAge && claims.auth_time) {
      validateAuthTime(claims.auth_time, maxAge);
    }

    // Validate azp if present and aud has multiple values
    if (claims.azp) {
      validateAuthorizedParty(claims.azp, expectedAudience, claims.aud);
    }

    return {
      valid: true,
      claims,
    };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Unknown validation error',
      errorCode: error instanceof Error ? error.name : 'unknown_error',
    };
  }
}
