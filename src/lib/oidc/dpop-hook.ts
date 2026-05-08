/**
 * React Hook for DPoP functionality
 *
 * @example
 * ```tsx
 * function MyComponent() {
 *   const { dpopFetch, isReady } = useDPoP();
 *
 *   const handleClick = async () => {
 *     const response = await dpopFetch('/api/users', {
 *       accessToken: session.access_token,
 *     });
 *   };
 *
 *   return <button onClick={handleClick} disabled={!isReady}>Fetch</button>;
 * }
 * ```
 */

'use client';

import { useState, useEffect } from 'react';
import {
  dpopFetch,
  getDPoPNonce,
  clearDPoPState,
  getOrCreateDPoPKeyPair,
} from './dpop-client';

export interface UseDPoPResult {
  /** Whether the DPoP key pair is ready */
  isReady: boolean;
  /** DPoP-protected fetch function */
  dpopFetch: typeof dpopFetch;
  /** Get the current DPoP nonce */
  getNonce: () => string | undefined;
  /** Clear DPoP state (for logout) */
  clearState: () => void;
}

export function useDPoP(): UseDPoPResult {
  const [isReady, setIsReady] = useState(false);

  useEffect(() => {
    getOrCreateDPoPKeyPair().then(() => setIsReady(true));
  }, []);

  return {
    isReady,
    dpopFetch,
    getNonce: getDPoPNonce,
    clearState: clearDPoPState,
  };
}
