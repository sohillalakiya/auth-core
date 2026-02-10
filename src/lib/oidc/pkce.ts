/**
 * PKCE (Proof Key for Code Exchange) Implementation
 *
 * Implements RFC 7636: PKCE OAuth 2.0 Extension for Authorization Code Flow.
 * This security extension prevents authorization code interception attacks.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7636
 */

import { createHash, randomBytes } from 'crypto';
import type { PKCECodePair } from './types';
import { PKCE_CONSTANTS, CODE_CHALLENGE_METHODS } from './constants';

/**
 * Code challenge methods
 */
export type CodeChallengeMethod = typeof CODE_CHALLENGE_METHODS[keyof typeof CODE_CHALLENGE_METHODS];

/**
 * Generates a cryptographically secure random code verifier.
 *
 * The code verifier is a cryptographically random string between 43 and 128
 * characters in length, using only unreserved characters (A-Z, a-z, 0-9, -, ., _, ~).
 *
 * @param length - The desired length of the code verifier (default: 128 for maximum security)
 * @returns A cryptographically random code verifier
 * @throws {Error} If the requested length is outside the valid range [43, 128]
 *
 * @example
 * ```ts
 * const verifier = generateCodeVerifier(); // 128 character string
 * const shortVerifier = generateCodeVerifier(64); // 64 character string
 * ```
 */
export function generateCodeVerifier(length: number = PKCE_CONSTANTS.VERIFIER_MAX_LENGTH): string {
  // Validate length is within RFC-specified bounds
  if (
    length < PKCE_CONSTANTS.VERIFIER_MIN_LENGTH ||
    length > PKCE_CONSTANTS.VERIFIER_MAX_LENGTH
  ) {
    throw new Error(
      `Code verifier length must be between ${PKCE_CONSTANTS.VERIFIER_MIN_LENGTH} and ${PKCE_CONSTANTS.VERIFIER_MAX_LENGTH} characters. Got: ${length}`
    );
  }

  // Generate cryptographically secure random bytes
  // We need more bytes than the final length because we'll filter to valid characters
  const byteLength = Math.ceil(length * 1.5); // Extra bytes to account for filtering
  const randomBytesBuffer = randomBytes(byteLength);

  // Convert to a string using only unreserved characters
  // Unreserved characters: A-Z, a-z, 0-9, -, ., _, ~ (66 characters total)
  const allowedChars = PKCE_CONSTANTS.ALLOWED_CHARS;
  const allowedCharsLength = allowedChars.length;
  let codeVerifier = '';

  for (let i = 0; i < randomBytesBuffer.length; i++) {
    // Use each byte as an index into the allowed characters
    const byte = randomBytesBuffer[i];
    const charIndex = byte % allowedCharsLength;
    codeVerifier += allowedChars[charIndex];

    if (codeVerifier.length >= length) {
      break;
    }
  }

  return codeVerifier;
}

/**
 * Generates a code challenge from a code verifier.
 *
 * The code challenge is derived from the code verifier using the specified method.
 * The S256 method (SHA-256) is recommended and widely supported.
 *
 * @param codeVerifier - The code verifier to transform
 * @param method - The challenge method to use (default: 'S256')
 * @returns The code challenge string
 * @throws {Error} If the method is not supported
 *
 * @example
 * ```ts
 * const verifier = generateCodeVerifier();
 * const challenge = generateCodeChallenge(verifier); // Uses S256 by default
 * const plainChallenge = generateCodeChallenge(verifier, 'plain');
 * ```
 */
export function generateCodeChallenge(
  codeVerifier: string,
  method: CodeChallengeMethod = 'S256'
): string {
  switch (method) {
    case 'S256':
      return generateCodeChallengeS256(codeVerifier);

    case 'plain':
      // The 'plain' method is NOT recommended but included for completeness
      // It simply returns the code verifier as-is
      return codeVerifier;

    default:
      throw new Error(
        `Unsupported code challenge method: ${method}. Supported methods are: S256, plain`
      );
  }
}

/**
 * Generates an S256 (SHA-256) code challenge.
 *
 * This is the recommended PKCE method. The code verifier is hashed using SHA-256,
 * then base64url-encoded (without padding).
 *
 * @param codeVerifier - The code verifier to transform
 * @returns The base64url-encoded SHA-256 hash of the code verifier
 *
 * @see https://www.rfc-editor.org/rfc/rfc7636#section-4.2
 */
export function generateCodeChallengeS256(codeVerifier: string): string {
  // Create SHA-256 hash of the code verifier
  const hash = createHash('sha256');
  hash.update(codeVerifier, 'utf8');
  const digest = hash.digest();

  // Base64url-encode the hash (without padding)
  // base64url = replace '+' with '-', '/' with '_', and remove trailing '='
  return digest
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Generates a complete PKCE code pair (verifier and challenge).
 *
 * This is a convenience function that generates both the code verifier and
 * its corresponding code challenge in one call.
 *
 * @param verifierLength - The desired length of the code verifier (default: 128)
 * @returns An object containing both the code verifier and code challenge
 *
 * @example
 * ```ts
 * const { code_verifier, code_challenge, code_challenge_method } = generatePKCECodePair();
 * ```
 */
export function generatePKCECodePair(
  verifierLength: number = PKCE_CONSTANTS.VERIFIER_MAX_LENGTH
): PKCECodePair {
  const codeVerifier = generateCodeVerifier(verifierLength);
  const codeChallenge = generateCodeChallenge(codeVerifier, 'S256');

  return {
    code_verifier: codeVerifier,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  };
}

/**
 * Validates whether a code verifier meets PKCE requirements.
 *
 * @param codeVerifier - The code verifier to validate
 * @returns true if the code verifier is valid, false otherwise
 *
 * @example
 * ```ts
 * if (isValidCodeVerifier(verifier)) {
 *   // Use the verifier
 * }
 * ```
 */
export function isValidCodeVerifier(codeVerifier: string): boolean {
  // Check length
  if (
    codeVerifier.length < PKCE_CONSTANTS.VERIFIER_MIN_LENGTH ||
    codeVerifier.length > PKCE_CONSTANTS.VERIFIER_MAX_LENGTH
  ) {
    return false;
  }

  // Check that all characters are unreserved characters
  const allowedChars = new Set(PKCE_CONSTANTS.ALLOWED_CHARS);
  for (const char of codeVerifier) {
    if (!allowedChars.has(char)) {
      return false;
    }
  }

  return true;
}

/**
 * Validates whether the provider supports a given code challenge method.
 *
 * @param method - The code challenge method to check
 * @param supportedMethods - Array of methods supported by the provider (from discovery)
 * @returns true if the method is supported, false otherwise
 *
 * @example
 * ```ts
 * const providerMetadata = await discoverProvider(issuer);
 * const isSupported = isCodeChallengeMethodSupported('S256', providerMetadata.code_challenge_methods_supported);
 * ```
 */
export function isCodeChallengeMethodSupported(
  method: CodeChallengeMethod,
  supportedMethods?: string[]
): boolean {
  if (!supportedMethods || supportedMethods.length === 0) {
    // If provider doesn't advertise supported methods, assume S256 is supported
    // (most providers support S256)
    return method === 'S256';
  }

  return supportedMethods.includes(method);
}

/**
 * Creates the code_challenge and code_challenge_method for the authorization request.
 *
 * This helper is typically used when building the authorization URL.
 *
 * @param codeVerifier - The stored code verifier from the initial auth request
 * @param supportedMethods - Optional array of provider-supported methods from discovery
 * @returns An object with code_challenge and code_challenge_method
 *
 * @example
 * ```ts
 * const { code_verifier } = authState; // Retrieved from storage
 * const { code_challenge, code_challenge_method } = createCodeChallengeForRequest(
 *   code_verifier,
 *   providerMetadata.code_challenge_methods_supported
 * );
 * ```
 */
export function createCodeChallengeForRequest(
  codeVerifier: string,
  supportedMethods?: string[]
): {
  code_challenge: string;
  code_challenge_method: CodeChallengeMethod;
} {
  // Determine which method to use
  let method: CodeChallengeMethod = 'S256'; // Default to S256

  if (!isCodeChallengeMethodSupported('S256', supportedMethods)) {
    // Fallback to plain if S256 is not supported (not recommended)
    if (isCodeChallengeMethodSupported('plain', supportedMethods)) {
      method = 'plain';
    } else {
      throw new Error(
        'Provider does not support any PKCE code challenge methods. PKCE cannot be used with this provider.'
      );
    }
  }

  const codeChallenge = generateCodeChallenge(codeVerifier, method);

  return {
    code_challenge: codeChallenge,
    code_challenge_method: method,
  };
}
