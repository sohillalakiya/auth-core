# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commit conventions

Never add `Co-Authored-By` or any Claude/AI attribution lines to commit messages.

## Code quality — mandatory before every commit

After any code change, always run both checks in order and fix all issues before committing:

```bash
pnpm lint       # must exit 0 — fix every error and warning, not just errors
pnpm build      # must succeed — fix any type errors or build failures
```

Do not commit if either command fails.

## Commands

```bash
pnpm dev          # Start development server (Next.js 16, port 3000)
pnpm build        # Production build
pnpm start        # Start production server
pnpm lint         # Run ESLint
```

There is no test runner configured. Before running the dev server, Redis must be available (see below).

### Local infrastructure

```bash
docker compose up -d    # Start Redis (port 6380) and RedisInsight UI (port 8001)
docker compose down     # Stop all services
```

Redis is mandatory — the app throws at startup if `REDIS_URL` is missing. Copy `.env.example` to `.env.local` and fill in all values before running. `SESSION_SECRET` must be at least 32 characters.

## Architecture

### What this is

A Next.js 16 App Router application implementing **OIDC Authorization Code Flow + PKCE from scratch** — no auth libraries. All RFC compliance is hand-rolled using only `jose` (JWT) and `ioredis` (Redis). The project is provider-agnostic and works with any OIDC-compliant provider (tested with Keycloak).

TypeScript path alias: `@/` maps to `src/`.

### Application pages

| Route | Auth required | Description |
|---|---|---|
| `/login` | No | Login landing page; redirects to `/` if already authenticated |
| `/` | Yes (in-component) | User dashboard showing profile and session info |
| `/todos` | Yes (in-component) | Todo list (localStorage-backed, API-validated) |
| `/auth/login` | No | Initiates OIDC flow |
| `/auth/callback` | No | OIDC callback handler |
| `/auth/logout` | No | RP-initiated logout |
| `/auth/backchannel-logout` | No | Receives server-to-server logout JWTs |
| `/api/todos` | Yes (manual check) | GET / POST todo items |
| `/api/todos/[id]` | Yes (manual check) | PATCH / DELETE a todo item |
| `/api/example/protected` | Yes (manual check) | Reference DPoP-protected API route |

### Auth flow end-to-end

1. `GET /auth/login` — builds the authorization URL (PKCE + state + nonce), generates DPoP key pair if `DPOP_ENABLED`, stores `AuthState` (including DPoP keys) in an encrypted HttpOnly cookie (`oidc_auth_state`), redirects to provider
2. `GET /auth/callback` — validates state (CSRF), generates DPoP proof from stored key pair if present, exchanges code for tokens, validates ID token (signature via JWKS + all claims), creates session (registered in Redis), sets encrypted `oidc_session` cookie
3. `GET /auth/logout` — RP-initiated logout: redirects to provider's `end_session_endpoint` with `id_token_hint`
4. `POST /auth/backchannel-logout` — receives logout JWTs from the provider (server-to-server), validates them, invalidates Redis session entries

### `src/lib/oidc/` — the core library

Every auth capability is in this library and exported from `index.ts`. Key modules:

| File | Responsibility |
|---|---|
| `env.ts` | Validates all env vars at startup; returns a cached `EnvConfig` |
| `cookie-encryption.ts` | AES-256-GCM cookie encryption via HKDF-SHA256 key derivation from `SESSION_SECRET`; all auth and session cookies are JWE compact-serialized (`dir` + `A256GCM`) |
| `discovery.ts` | Fetches and caches provider metadata from `.well-known/openid-configuration`; includes helpers for backchannel logout and DPoP support detection |
| `pkce.ts` | Generates PKCE `code_verifier` / `code_challenge` (S256) |
| `state.ts` | Generates and validates CSRF state + nonce |
| `authorization.ts` | Builds the full authorization URL; accepts optional `dpopJkt` to append `dpop_jkt` param |
| `tokens.ts` | Exchanges authorization code for tokens; handles token refresh. Falls back to `{issuer}/protocol/openid-connect/token` (Keycloak path) if no token endpoint is explicitly passed |
| `validation.ts` | Full ID token validation: decodes JWT, fetches JWKS, verifies signature, validates all standard claims |
| `jwks.ts` | Fetches and caches JWKS from the provider |
| `cookies.ts` | Type-safe cookie helpers; all reads/writes go through `cookie-encryption.ts`; `getSessionCookie()` also performs backchannel-invalidation check against Redis |
| `session.ts` | Session lifecycle: `createSessionData()` (async — registers in Redis before returning), `getSession()` (simple cookie read), `getValidSessionWithRefresh()` (auto-refreshes on expiry), `destroySession()` |
| `session-registry.ts` | `RedisSessionRegistry` — tracks active sessions in Redis for backchannel logout; also serves as JTI replay-protection cache. `isValid()` checks only the `invalidated` flag — a session absent from Redis is still considered valid (cookie `expires_at` is the primary expiry) |
| `backchannel-logout.ts` | Validates logout JWTs (signature, claims, JTI replay) and calls registry to invalidate |
| `logout.ts` | Builds RP-initiated logout URLs |
| `userinfo.ts` | Fetches and caches UserInfo endpoint claims |
| `dpop.ts` | DPoP key generation (ES256), proof generation and verification per RFC 9449. Always pass `'ES256'` as second arg to `importJWK` — `exportJWK` intentionally omits `alg` |
| `dpop-middleware.ts` | `withDPoP()` higher-order function wrapping Next.js route handlers with DPoP validation. Uses in-memory Maps for nonce and proof replay caches — not suitable for multi-instance deployments as-is |
| `dpop-client.ts` | `dpopFetch()` — drop-in replacement for `fetch` that attaches a DPoP proof header using the in-memory key pair from `useDPoP` |
| `dpop-hook.ts` | `useDPoP()` React hook — generates and stores an ES256 key pair in memory on first render; exposes `isReady` until the async generation completes |
| `errors.ts` | Typed error classes (`OIDCError`, `ConfigurationError`, etc.) and error formatting |
| `constants.ts` | All shared constants — cookie names, routes, time windows, Redis key prefixes |
| `types.ts` | All TypeScript interfaces — `SessionData`, `AuthState` (includes optional `dpop_private_key`, `dpop_public_key`, `dpop_jkt`), `IDTokenClaims`, `LogoutTokenClaims`, DPoP types, etc. |

### Import paths

`index.ts` re-exports almost everything, but two items are **not** in `index.ts` and must be imported directly:

- `getSession` — import from `@/lib/oidc/session` (not `@/lib/oidc`)
- `DPoPError` — import from `@/lib/oidc/types` (defined there but not re-exported from index)

### Cookie encryption

All cookies (`oidc_auth_state`, `oidc_session`) are encrypted before being sent to the browser and decrypted on read. The encryption is handled by `cookie-encryption.ts`:

- Key derivation: HKDF-SHA256 from `SESSION_SECRET` with salt `oidc-cookie-encryption` and info `v1`
- Cipher: AES-256-GCM via `jose` `CompactEncrypt` / `compactDecrypt` (`dir` + `A256GCM`)
- The derived key is cached in-process after first derivation

JWE compact serialization adds ~33% base64url overhead to plaintext size. If `SESSION_SECRET` changes, all existing cookies are immediately invalidated (decryption returns `undefined`).

### Session storage model

Sessions are **stateless cookies** (`oidc_session`) containing an encrypted JSON `SessionData` blob — no server-side session store for the session itself. The cookie stores tokens, user claims, expiry, and a `sid` (session ID). DPoP public key info (`dpop_jkt`, `dpop_public_key`, `dpop_key_created_at`) is also stored in `SessionData` when DPoP is enabled.

Redis is used **only for backchannel logout** via `RedisSessionRegistry`:
- `oidc_session:s:{sid}` — session hash (sub, provider, timestamps)
- `oidc_session:s:{sid}:invalidated` — flag set when backchannel logout fires
- `oidc_session:jti:{jti}` — replay-protection cache for logout token JTIs
- `oidc_session:sub:{sub}` — set of SIDs per user (for global logout)

When `getSessionCookie()` is called, it checks Redis for an invalidation flag. If found, the session is treated as absent, forcing re-authentication on the next request.

Use `getSession()` (from `@/lib/oidc/session`) when you only need to read the current session without potentially triggering a token refresh. Use `getValidSessionWithRefresh()` in route handlers and Server Components where an expiring token should be refreshed transparently.

### Startup

`src/instrumentation.ts` runs once when the Next.js server starts (Node.js runtime only). It validates the config and warms up the Redis connection so the first request doesn't pay connection latency. Redis event logs (`connect`, `ready`, `error`, `reconnecting`) come from `RedisSessionRegistry` event listeners.

### Route protection — two strategies

**In-component protection (current default for pages):** Server Components (`/`, `/todos`) call `getSession()` directly and `redirect('/login')` when absent. This is the primary guard for all rendered pages.

**Middleware protection via `proxy.ts`:** `proxy.ts` at the project root defines a Next.js middleware that decrypts `oidc_session` and redirects unauthenticated users. It only runs on routes listed in the `PROTECTED_ROUTES` array (currently `['/user']`). No Redis check happens in middleware — that happens only in Route Handlers and Server Components.

**To activate middleware protection**, create `src/middleware.ts` that imports and re-exports `proxy`:

```ts
export { proxy as middleware, config } from './proxy';
```

**To add more middleware-protected routes**, edit `PROTECTED_ROUTES` at the top of `proxy.ts`. All `/auth/*`, `/api/auth/*`, and `/login` paths are unconditionally public via `PUBLIC_ROUTES` in the same file. API routes and `/_next/*` are skipped entirely by the middleware matcher.

### Todos feature

`/todos` is a client-side todo list backed by `localStorage` (key: `oidc_todos`). The API routes (`/api/todos`, `/api/todos/[id]`) act as auth gatekeepers — the server echoes back payloads rather than persisting them; state lives entirely in the browser.

`src/app/todos/TodoList.tsx` is a Client Component that demonstrates the client-side DPoP pattern:
- Calls `useDPoP()` to generate an in-memory key pair; gates interactions on `isReady`
- Calls `dpopFetch(url, { ...init, accessToken })` instead of bare `fetch` when `DPOP_ENABLED`
- Uses absolute URLs (required by `dpopFetch` for proof binding)

### DPoP (RFC 9449)

DPoP is opt-in, controlled by `DPOP_ENABLED` env var. When enabled:
- At login: an ES256 key pair is generated and stored (encrypted) in the `AuthState` cookie along with the JKT thumbprint
- At callback: the stored key pair is used to generate a DPoP proof for `POST {token_endpoint}`; DPoP public key info is written into `SessionData`
- For API calls (server-side): `withDPoP()` wraps route handlers, validates proofs, enforces nonce rotation, and detects JTI replay
- For API calls (client-side): `useDPoP()` + `dpopFetch()` manage the key pair and proof generation in the browser

`src/app/api/example/protected/route.ts` is the reference for `withDPoP()` on a route handler. `src/app/todos/TodoList.tsx` is the reference for client-side DPoP with `useDPoP` + `dpopFetch`. The nonce and JTI replay caches inside `dpop-middleware.ts` are in-memory Maps — running multiple server instances requires replacing them with a shared store (e.g. Redis).

### Next.js 16 redirect handling

`redirect()` from `next/navigation` throws a `NEXT_REDIRECT` error. All route handlers catch and re-throw it explicitly:

```ts
if (error?.digest?.startsWith('NEXT_REDIRECT')) throw error;
```

This pattern appears in every route handler — do not remove it or wrap it in a generic catch.

## Environment variables

All variables are validated in `env.ts`; the app fails fast with a descriptive error if any are missing.

| Variable | Required | Notes |
|---|---|---|
| `OIDC_ISSUER` | Yes | Provider base URL; trailing slash stripped |
| `OIDC_CLIENT_ID` | Yes | |
| `OIDC_CLIENT_SECRET` | No | Empty string treated as absent (public client) |
| `OIDC_REDIRECT_URI` | Yes | Must match provider registration exactly |
| `OIDC_POST_LOGOUT_REDIRECT_URI` | Yes | |
| `OIDC_SCOPE` | Yes | Must include `openid` |
| `SESSION_SECRET` | Yes | Min 32 chars; used as HKDF input for cookie encryption key |
| `REDIS_URL` | Yes | `redis://` or `rediss://` scheme |
| `DPOP_ENABLED` | No | `true`/`1` to enable DPoP key binding on token requests |
