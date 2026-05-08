/**
 * DPoP (Demonstrating Proof-of-Possession) implementation
 * RFC 9449: https://datatracker.ietf.org/doc/html/rfc9449
 */

import {
  generateKeyPair,
  exportJWK,
  SignJWT,
  jwtVerify,
  importJWK,
  type JWTHeaderParameters,
  type JWTPayload,
} from 'jose';

export interface DPoPKeyPair {
  privateKey: string;
  publicKey: string;
  jkt: string; // JWT thumbprint for confirmation
}

export interface DPoPHeaderOptions {
  htu: string; // HTTP URI
  htm: string; // HTTP method
  dpopNonce?: string;
  ath?: string; // Access token hash
}

export interface DPoPProof {
  proof: string;
  jkt: string;
}

export interface DPoPPayload extends JWTPayload {
  jti: string;
  htm: string;
  htu: string;
  iat: number;
  nonce?: string;
  ath?: string;
}

// Cache for key pairs per session
const keyCache = new Map<string, DPoPKeyPair>();

/**
 * Generate a new ES256 key pair for DPoP
 */
export async function generateDPoPKeyPair(): Promise<DPoPKeyPair> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', {
    extractable: true,
  });

  const privateJwk = await exportJWK(privateKey);
  const publicJwk = await exportJWK(publicKey);

  // Calculate JKT (JWT Thumbprint) - RFC 7638
  const jkt = await calculateJKT(publicJwk);

  return {
    privateKey: JSON.stringify(privateJwk),
    publicKey: JSON.stringify(publicJwk),
    jkt,
  };
}

/**
 * JWK type for thumbprint calculation
 */
type JWKThumbprintKey = {
  kty?: string;
  crv?: string;
  n?: string;
  e?: string;
  x?: string;
  y?: string;
};

/**
 * Calculate JWT Thumbprint (JKT) of a public key
 * RFC 7638 compliant
 */
async function calculateJKT(publicJwk: JWKThumbprintKey): Promise<string> {
  const { kty, crv, n, e, x, y } = publicJwk;

  if (!kty) {
    throw new Error('Invalid JWK: missing kty');
  }

  let canonicalJwk: Record<string, string>;
  if (kty === 'RSA') {
    canonicalJwk = { e: e || '', kty, n: n || '' };
  } else if (kty === 'EC' && (crv === 'P-256' || crv === 'P-384' || crv === 'P-521')) {
    canonicalJwk = { crv: crv || '', kty, x: x || '', y: y || '' };
  } else {
    throw new Error(`Unsupported key type: ${kty}${crv ? ` (${crv})` : ''}`);
  }

  const canonicalJson = JSON.stringify(canonicalJwk);
  const data = new TextEncoder().encode(canonicalJson);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(digest));
}

function base64UrlEncode(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Generate a DPoP proof JWT
 */
export async function generateDPoPProof(
  keyPair: DPoPKeyPair,
  options: DPoPHeaderOptions
): Promise<string> {
  const privateKey = await importJWK(JSON.parse(keyPair.privateKey), 'ES256');
  const publicJwk = JSON.parse(keyPair.publicKey) as JWKThumbprintKey;

  // Generate unique JTI for replay protection
  const jti = crypto.randomUUID();

  const now = Math.floor(Date.now() / 1000);

  const payload: DPoPPayload = {
    jti,
    htm: options.htm,
    htu: options.htu,
    iat: now,
  };

  if (options.dpopNonce) {
    payload.nonce = options.dpopNonce;
  }

  if (options.ath) {
    payload.ath = options.ath;
  }

  const header: JWTHeaderParameters = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: publicJwk,
  };

  const proof = await new SignJWT(payload)
    .setProtectedHeader(header)
    .sign(privateKey);

  return proof;
}

/**
 * Verify a DPoP proof JWT
 */
export async function verifyDPoPProof(
  proof: string,
  expectedHtu: string,
  expectedHtm: string,
  maxAgeSeconds: number = 30
): Promise<{
  valid: boolean;
  jkt: string;
  payload?: DPoPPayload;
  error?: string;
}> {
  try {
    // Decode header to get JWK without verification first
    const parts = proof.split('.');
    if (parts.length !== 3) {
      return { valid: false, jkt: '', error: 'Invalid JWT format' };
    }

    const header = JSON.parse(atob(parts[0]));

    if (header.typ !== 'dpop+jwt') {
      return { valid: false, jkt: '', error: 'Invalid typ header' };
    }

    if (!header.jwk) {
      return { valid: false, jkt: '', error: 'Missing jwk in header' };
    }

    // Calculate JKT
    const jkt = await calculateJKT(header.jwk);

    // Import key for verification
    const publicKey = await importJWK(header.jwk, 'ES256');

    // Verify JWT signature
    const { payload } = await jwtVerify(proof, publicKey, {
      typ: 'dpop+jwt',
    });

    // Check HTU (HTTP URI)
    if (payload.htu !== expectedHtu) {
      return { valid: false, jkt, error: 'HTU mismatch' };
    }

    // Check HTM (HTTP method)
    if (payload.htm !== expectedHtm) {
      return { valid: false, jkt, error: 'HTM mismatch' };
    }

    // Check freshness (iat)
    const now = Math.floor(Date.now() / 1000);
    const iat = typeof payload.iat === 'number' ? payload.iat : 0;
    if (now - iat > maxAgeSeconds) {
      return { valid: false, jkt, error: 'Proof expired' };
    }

    // Check future iat (clock skew)
    if (iat > now + 5) {
      return { valid: false, jkt, error: 'Proof from future' };
    }

    return { valid: true, jkt, payload: payload as DPoPPayload };
  } catch (error) {
    return {
      valid: false,
      jkt: '',
      error: error instanceof Error ? error.message : 'Verification failed',
    };
  }
}

/**
 * Hash access token for ATH claim
 * SHA-256 hash of base64url-encoded access token
 */
export async function hashAccessToken(token: string): Promise<string> {
  const data = new TextEncoder().encode(token);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(digest));
}

/**
 * Store key pair for a session
 */
export function storeKeyPair(sessionId: string, keyPair: DPoPKeyPair): void {
  keyCache.set(sessionId, keyPair);
}

/**
 * Get key pair for a session
 */
export function getKeyPair(sessionId: string): DPoPKeyPair | undefined {
  return keyCache.get(sessionId);
}

/**
 * Remove key pair for a session
 */
export function removeKeyPair(sessionId: string): void {
  keyCache.delete(sessionId);
}

/**
 * Generate or retrieve existing key pair for session
 */
export async function getOrCreateKeyPair(sessionId: string): Promise<DPoPKeyPair> {
  let keyPair = keyCache.get(sessionId);
  if (!keyPair) {
    keyPair = await generateDPoPKeyPair();
    keyCache.set(sessionId, keyPair);
  }
  return keyPair;
}
