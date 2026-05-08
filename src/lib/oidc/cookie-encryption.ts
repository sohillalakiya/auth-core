/**
 * Cookie encryption using AES-256-GCM (JWE compact serialization).
 * Key is derived from SESSION_SECRET via HKDF-SHA256.
 * Uses jose + Web Crypto API — compatible with both Node.js and Edge Runtime.
 */

import { CompactEncrypt, compactDecrypt } from 'jose';
import { getConfig } from './env';

let cachedKeyBytes: Uint8Array | null = null;

async function getKeyBytes(): Promise<Uint8Array> {
  if (cachedKeyBytes) return cachedKeyBytes;

  const { sessionSecret } = getConfig();

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(sessionSecret),
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('oidc-cookie-encryption'),
      info: new TextEncoder().encode('v1'),
    },
    keyMaterial,
    256
  );

  cachedKeyBytes = new Uint8Array(bits);
  return cachedKeyBytes;
}

export async function encryptCookieValue(plaintext: string): Promise<string> {
  const key = await getKeyBytes();
  return new CompactEncrypt(new TextEncoder().encode(plaintext))
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .encrypt(key);
}

/**
 * Returns undefined if decryption fails (e.g. tampered, wrong key, or legacy plaintext cookie).
 */
export async function decryptCookieValue(ciphertext: string): Promise<string | undefined> {
  try {
    const key = await getKeyBytes();
    const { plaintext } = await compactDecrypt(ciphertext, key);
    return new TextDecoder().decode(plaintext);
  } catch {
    return undefined;
  }
}
