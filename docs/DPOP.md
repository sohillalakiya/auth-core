# DPoP (Demonstrating Proof-of-Possession)

**RFC 9449** — Binds an access token to a specific key pair so that a stolen token is useless without the matching private key. Every request must include a short-lived proof JWT signed by that private key.

---

## How It Works in One Sentence

At login the server generates an ES256 key pair, binds the future access token to that key's thumbprint at the provider, then discards the private key. For API calls, the browser generates its own independent key and signs a fresh proof for every request.

---

## Two Independent DPoP Contexts

This codebase runs DPoP at two separate layers. Understanding this distinction is essential.

| Layer | When | Key location | What it protects |
|---|---|---|---|
| **Provider binding** | Login → Callback (server) | Encrypted in `oidc_auth_state` cookie, then deleted | Binds the provider-issued access token to a key thumbprint — token unusable without key |
| **API route protection** | Browser → Next.js route handlers | In-memory via `useDPoP()` | Proves the browser client holds a key on every call to our own routes |

---

## End-to-End Flow

```
Browser                         Our Server (Next.js)              OIDC Provider
   │                                    │                               │
   │── GET /auth/login ──────────────>  │                               │
   │                         [server] generateDPoPKeyPair()             │
   │                         ES256 key pair → encrypted AuthState cookie│
   │                         dpop_jkt = SHA256(canonical public JWK)    │
   │<── 302 → provider?dpop_jkt=ABC ──  │                               │
   │                                    │                               │
   │── follows redirect ──────────────────────────────────────────────> │
   │<── 302 /auth/callback?code=XYZ ──────────────────────────────────  │
   │                                    │                               │
   │── GET /callback?code=XYZ ────────> │                               │
   │                         read key pair from AuthState cookie        │
   │                         generateDPoPProof(htm=POST, htu=/token)    │
   │                         POST /token + DPoP: <proof> ─────────────> │
   │                                    │              verify proof matches dpop_jkt
   │                                    │<── DPoP-bound access_token ── │
   │                         write dpop_jkt + dpop_public_key           │
   │                         into SessionData (private key discarded)   │
   │<── set oidc_session cookie ──────  │                               │
   │                                    │                               │
   │  [on /todos page]                  │                               │
   │  useDPoP() generates NEW browser key pair                          │
   │  (independent of the login key)    │                               │
   │                                    │                               │
   │── POST /api/todos                  │                               │
   │   Authorization: Bearer <token>    │                               │
   │   DPoP: <proof signed by browser key, ath=SHA256(token)> ───────> │
   │                         withDPoP() validates:                      │
   │                           ✓ typ = dpop+jwt                         │
   │                           ✓ signature over public key in header    │
   │                           ✓ htm = POST, htu = /api/todos           │
   │                           ✓ iat ≤ 30 seconds ago                  │
   │                           ✓ jti not seen before (replay check)     │
   │                           ✓ ath = SHA256(access_token)             │
   │<── 201 + DPoP-Nonce: <new> ──────  │                               │
   │  store nonce for next request      │                               │
```

---

## Phase 1 — Login: Key Generation

**File:** `src/app/auth/login/route.ts:119-128`

```ts
if (config.dpopEnabled) {
  const dpopKeyPair = await generateDPoPKeyPair();
  authState.dpop_private_key = dpopKeyPair.privateKey;
  authState.dpop_public_key  = dpopKeyPair.publicKey;
  authState.dpop_jkt         = dpopKeyPair.jkt;
  dpopJkt = dpopKeyPair.jkt;
}
```

`generateDPoPKeyPair()` — **`src/lib/oidc/dpop.ts:49-65`**

```ts
const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
const publicJwk = await exportJWK(publicKey);
const jkt = await calculateJKT(publicJwk);  // RFC 7638 thumbprint
return { privateKey: JSON.stringify(privateJwk), publicKey: JSON.stringify(publicJwk), jkt };
```

**JKT calculation** — `dpop.ts:83-103`

The thumbprint is a SHA-256 hash of the canonical public key JSON (fields sorted: `crv`, `kty`, `x`, `y`), base64url-encoded. It is a stable, short identifier for a public key.

```ts
const canonicalJwk = { crv, kty, x, y };                     // sorted, no extras
const digest = await crypto.subtle.digest('SHA-256', encode(JSON.stringify(canonicalJwk)));
return base64UrlEncode(new Uint8Array(digest));
```

The entire key pair plus JKT is stored **encrypted** in the `oidc_auth_state` HttpOnly cookie (JWE / AES-256-GCM). The JKT is also appended to the authorization URL:

```ts
// src/lib/oidc/authorization.ts
authorizationUrl.searchParams.set('dpop_jkt', dpopJkt);
```

This tells the provider: _"when you issue tokens after this auth, bind them to this key thumbprint."_

---

## Phase 2 — Callback: Token Exchange with DPoP Proof

**File:** `src/app/auth/callback/route.ts:169-190`

```ts
// Retrieve key pair from the encrypted AuthState cookie
if (authState.dpop_private_key && authState.dpop_public_key && authState.dpop_jkt) {
  dpopProof = await generateDPoPProof(
    {
      privateKey: authState.dpop_private_key,
      publicKey:  authState.dpop_public_key,
      jkt:        authState.dpop_jkt,
    },
    {
      htm: 'POST',
      htu: provider.token_endpoint,  // exact URL — htu must match
    }
  );
}
```

**What `generateDPoPProof()` produces** — `dpop.ts:115-153`

```
Header: {
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": { "kty":"EC", "crv":"P-256", "x":"...", "y":"..." }  ← public key embedded
}

Payload: {
  "jti": "550e8400-e29b-41d4-a716-446655440000",   ← UUID, single-use
  "htm": "POST",                                    ← HTTP method
  "htu": "https://idp.example/realms/x/token",     ← exact endpoint URL
  "iat": 1715123456                                 ← must be ≤ 30s old
}

Signature: ES256(privateKey, base64url(header) + "." + base64url(payload))
```

The proof is sent as the `DPoP` header in the token request — `tokens.ts:134-137`:

```ts
if (dpopProof) {
  headers['DPoP'] = dpopProof;
}
```

The provider verifies the proof's signature against the public key in the header, and checks that the public key's thumbprint matches the `dpop_jkt` it received during authorization. If both match, it issues a DPoP-bound access token (token type `"DPoP"` instead of `"Bearer"`).

After the exchange, the **public key info** is written into `SessionData` — `callback/route.ts:210-214`:

```ts
sessionData.dpop_jkt          = authState.dpop_jkt;
sessionData.dpop_public_key   = authState.dpop_public_key;
sessionData.dpop_key_created_at = Date.now();
```

> **The private key is never stored in `SessionData`.** The `AuthState` cookie is deleted immediately (`deleteAuthStateCookie()`). The provider-layer DPoP work is complete.

---

## Phase 3 — Browser: Client-Side Key Generation

For calls to our own Next.js API routes, the browser generates a **fresh, independent key pair** using the `useDPoP()` hook.

**File:** `src/lib/oidc/dpop-hook.ts:41-53`

```ts
export function useDPoP(): UseDPoPResult {
  const [isReady, setIsReady] = useState(false);

  useEffect(() => {
    // Generates an ES256 key pair and holds it in module-level state
    getOrCreateDPoPKeyPair().then(() => setIsReady(true));
  }, []);

  return { isReady, dpopFetch, getNonce: getDPoPNonce, clearState: clearDPoPState };
}
```

**File:** `src/lib/oidc/dpop-client.ts:25-40`

```ts
const state: DPoPClientState = { keyPair: null, nonce: null, lastNonceTime: 0 };

export async function getOrCreateDPoPKeyPair(): Promise<DPoPKeyPair> {
  if (!state.keyPair) {
    state.keyPair = await generateDPoPKeyPair();
  }
  return state.keyPair;
}
```

The key pair lives in a module-level variable — it persists for the lifetime of the browser tab but is never written to `localStorage` or cookies.

In `TodoList.tsx`, all interactions are blocked until the key is ready:

```ts
const { isReady } = useDPoP();
const dpopReady = !dpopEnabled || isReady;

// Every button: disabled={busy || !dpopReady}
```

---

## Phase 4 — Making a DPoP-Protected API Call

**File:** `src/app/todos/TodoList.tsx:54-63`

```ts
const call = useCallback(
  (path: string, init: RequestInit = {}): Promise<Response> => {
    if (dpopEnabled) {
      const url = `${window.location.origin}${path}`;  // absolute URL required for htu
      return dpopFetch(url, { ...init, accessToken });
    }
    return fetch(path, init);
  },
  [dpopEnabled, accessToken],
);
```

`dpopFetch()` — **`src/lib/oidc/dpop-client.ts:156-228`**

```ts
// 1. Reuse the in-memory key pair
const keyPair = await getOrCreateDPoPKeyPair();

// 2. Hash the access token → ath claim
//    Binds this proof to this specific token — proof is useless with a different token
const ath = await hashAccessToken(accessToken);  // SHA-256(access_token), base64url

// 3. Sign a fresh proof for this specific (method, URL) pair
const proof = await generateDPoPProof(keyPair, {
  htu: url,           // "https://localhost:3000/api/todos"
  htm: method,        // "POST"
  dpopNonce: nonce,   // server-issued nonce (empty on first call)
  ath,
});

// 4. Attach both headers
const response = await fetch(url, {
  ...fetchOptions,
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'DPoP': proof,
  },
});

// 5. Capture the server's new nonce for the next call
const responseNonce = response.headers.get('dpop-nonce');
if (responseNonce) updateDPoPNonce(responseNonce);
```

**Automatic nonce retry** — `dpop-client.ts:207-226`

If the server responds `401 use_dpop_nonce` (nonce was stale or absent), `dpopFetch` retries once with the fresh nonce from the response:

```ts
if (response.status === 401 && responseNonce && maxRetries > 0) {
  const errorData = await response.clone().json();
  if (errorData.error === 'use_dpop_nonce' || errorData.error === 'invalid_dpop_proof') {
    return dpopFetch(url, { ...options, nonce: responseNonce, maxRetries: maxRetries - 1 });
  }
}
```

---

## Phase 5 — Server Validates the Proof

Route handlers are wrapped with `withDPoP()` — **`src/lib/oidc/dpop-middleware.ts:241-297`**

```ts
// src/app/api/todos/route.ts
export const POST = withDPoP({
  enabled: dpopEnabled,
  required: dpopEnabled,                                      // mandatory when DPoP is on
  getJkt: async () => (await getSession())?.dpop_jkt,         // expected key thumbprint
  getAccessToken: async () => (await getSession())?.access_token,
})(postHandler);
```

`validateDPoPFromRequest()` — **`dpop-middleware.ts:98-159`** — runs these checks in order:

```ts
// 1. Header must exist
const dpopHeader = request.headers.get('dpop');
if (!dpopHeader) return { valid: false, error: 'Missing DPoP header' };

// 2. Verify JWT: signature, typ=dpop+jwt, htm, htu, iat freshness (≤ 30s, no future iat)
const result = await verifyDPoPProof(dpopHeader, request.url, request.method, maxAgeSeconds);

// 3. JTI replay check — was this exact proof used before?
if (isProofReplay(result.payload.jti)) {
  return { valid: false, error: 'Replay detected: proof JTI already used' };
}

// 4. ATH check — does SHA-256(access_token) match the proof's ath claim?
const expectedAth = await hashAccessToken(options.accessToken);
if (result.payload.ath !== expectedAth) {
  return { valid: false, error: 'Access token hash mismatch' };
}

// 5. JKT check — does the proof's public key match the expected session key?
if (options.expectedJkt && result.jkt !== options.expectedJkt) {
  return { valid: false, error: 'JKT mismatch: proof key does not match session key' };
}

// 6. Mark JTI used (auto-expires from Set after 60s)
markProofUsed(result.payload.jti);
```

On success, the handler runs and the response always includes a fresh nonce:

```ts
response.headers.set('DPoP-Nonce', generateDPoPNonce());
```

**Nonce lifecycle** — `dpop-middleware.ts:15-51`

```ts
const nonceCache = new Map<string, { expiresAt: number }>();
const NONCE_EXPIRY_MS = 5 * 60 * 1000;  // 5 minutes

function generateDPoPNonce(): string {
  const nonce = crypto.randomUUID();
  nonceCache.set(nonce, { expiresAt: Date.now() + NONCE_EXPIRY_MS });
  return nonce;
}

function isValidNonce(nonce: string): boolean {
  const entry = nonceCache.get(nonce);
  if (!entry) return false;
  nonceCache.delete(nonce);  // single-use
  return Date.now() < entry.expiresAt;
}
```

---

## DPoP Proof Structure Reference

```
eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Li4ufX0   ← header (base64url)
.
eyJqdGkiOiI1NTBlODQwMC4uLiIsImh0bSI6IlBPU1QiLCJodHUiOiJodH   ← payload (base64url)
RwczovL2xvY2FsaG9zdDozMDAwL2FwaS90b2RvcyIsImlhdCI6MTcxNTEyMz
Q1NiwiYXRoIjoiQUJDMTIzLi4uIn0
.
<ES256 signature>
```

Decoded header:
```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
}
```

Decoded payload:
```json
{
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "htm": "POST",
  "htu": "https://localhost:3000/api/todos",
  "iat": 1715123456,
  "ath": "abc123..."
}
```

---

## Error Responses

| HTTP | `error` field | Cause | Client action |
|---|---|---|---|
| `401` | `invalid_dpop_proof` | Bad signature, wrong htm/htu, expired iat, replay | Regenerate proof |
| `400` | `use_dpop_nonce` | Missing or expired nonce | Retry with `DPoP-Nonce` from response header |
| `401` | `invalid_dpop_proof` | ATH mismatch | Verify access token matches the one in session |
| `401` | `invalid_dpop_proof` | JKT mismatch | Key pair is wrong for this session |

`dpopFetch` handles the `use_dpop_nonce` case automatically (1 retry). All other errors propagate as thrown exceptions.

---

## Known Limitation: JKT Context Mismatch

The `dpop_jkt` stored in `SessionData` comes from the **server-side login key pair** (used to bind the provider's token). The **browser key pair** from `useDPoP()` is generated independently and has a different JKT.

When `withDPoP` calls `getJkt: async () => session?.dpop_jkt`, it gets the server key's thumbprint. The browser proof carries a different thumbprint. The JKT check at step 5 of validation will therefore fail when `DPOP_ENABLED=true` and `session.dpop_jkt` is set.

The ATH (access token hash), signature, htm, htu, iat, and JTI replay checks all work correctly. The JKT binding between the provider-issued token and our own API routes would require either:
- Storing the browser's public key server-side during a registration step
- Skipping the JKT check on our own routes (`getJkt: async () => undefined`)

---

## Multi-Instance Limitation

The nonce cache (`nonceCache`) and JTI replay set (`USED_PROOFS`) in `dpop-middleware.ts` are **in-memory Maps**. Running more than one Next.js server instance means each instance has its own caches — a nonce issued by instance A is unknown to instance B.

For horizontal scaling, replace both structures with a shared Redis store (same pattern as `RedisSessionRegistry`).

---

## Configuration

Set in `.env.local`:

```bash
DPOP_ENABLED=true   # "true" or "1" — anything else disables DPoP
```

When `DPOP_ENABLED` is not set or false:
- `withDPoP({ enabled: false })` passes all requests through without any DPoP check
- `useDPoP()` still runs (rules of hooks), but `dpopReady` is `true` immediately and plain `fetch` is used instead of `dpopFetch`
- No key pairs are generated at login, and `SessionData` carries no DPoP fields

---

## Relevant Files

| File | Role |
|---|---|
| `src/lib/oidc/dpop.ts` | Key generation, proof generation, proof verification, JKT calculation |
| `src/lib/oidc/dpop-middleware.ts` | `withDPoP()` HOF, nonce cache, JTI replay set, error responses |
| `src/lib/oidc/dpop-client.ts` | `dpopFetch()`, in-memory client state, nonce management |
| `src/lib/oidc/dpop-hook.ts` | `useDPoP()` React hook |
| `src/app/auth/login/route.ts` | Server-side key pair generation at login start |
| `src/app/auth/callback/route.ts` | DPoP proof for token exchange, JKT written to session |
| `src/lib/oidc/tokens.ts` | Adds `DPoP` header to token endpoint request |
| `src/app/api/todos/route.ts` | Reference: `withDPoP()` on mutating routes |
| `src/app/api/example/protected/route.ts` | Reference: `withDPoP()` on a GET route |
| `src/app/todos/TodoList.tsx` | Reference: `useDPoP()` + `dpopFetch()` in a Client Component |

---

## References

- [RFC 9449 — OAuth 2.0 Demonstrating Proof-of-Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 7638 — JSON Web Key (JWK) Thumbprint](https://www.rfc-editor.org/rfc/rfc7638)
