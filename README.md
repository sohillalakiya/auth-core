# Auth Core

A Next.js 16 application implementing OpenID Connect (OIDC) authentication from scratch, following RFC standards without any third-party authentication libraries.

## Overview

This project demonstrates a complete OIDC Authorization Code Flow with PKCE implementation using:

- **Next.js 16** with App Router
- **TypeScript** for type safety
- **Tailwind CSS v4** for styling
- **Zero auth libraries** - pure RFC-compliant implementation

## Features

- **OIDC Authorization Code Flow with PKCE** (RFC 7636)
- **Stateless session management** using encrypted HttpOnly cookies
- **ID Token validation** per RFC 7519 (JWT)
- **RP-Initiated Logout** (OpenID Connect RP-Initiated Logout 1.0)
- **Silent token refresh** using refresh tokens
- **Protected routes** with middleware
- **Provider-agnostic** - works with any OIDC-compliant provider

## Pages

| Route | Access | Description |
|-------|--------|-------------|
| `/` | Public | Homepage with login button |
| `/user` | Protected | User profile page (requires auth) |
| `/auth/login` | Public | Initiates OIDC login flow |
| `/auth/callback` | Public | OAuth callback handler |
| `/auth/logout` | Public | Logout handler |

## Documentation

See [docs/OIDC_AUTHENTICATION.md](./docs/OIDC_AUTHENTICATION.md) for complete functional documentation including:

- RFC standards covered
- Storage architecture
- Implementation phases
- Security considerations

## Getting Started

1. Copy `.env.example` to `.env.local`
2. Configure your OIDC provider settings
3. Run `npm install`
4. Run `npm run dev`

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser.

## Environment Variables

```env
OIDC_ISSUER=https://your-oidc-provider.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=http://localhost:3000/auth/callback
OIDC_POST_LOGOUT_REDIRECT_URI=http://localhost:3000
OIDC_SCOPE=openid profile email
SESSION_SECRET=your-random-32-character-secret-string
```

## Tech Stack

- **Next.js 16.1** - React framework
- **React 19** - UI library
- **TypeScript** - Type safety
- **Tailwind CSS v4** - Styling
