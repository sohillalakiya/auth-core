/**
 * OIDC Constants
 *
 * Standard constants for OpenID Connect authentication.
 * These values align with OIDC and OAuth 2.0 specifications.
 */

// =============================================================================
// Standard OIDC Scopes
// =============================================================================

/**
 * Standard OpenID Connect scopes
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
 */
export const OIDC_SCOPES = {
  OPENID: 'openid',
  PROFILE: 'profile',
  EMAIL: 'email',
  ADDRESS: 'address',
  PHONE: 'phone',
  OFFLINE_ACCESS: 'offline_access',
} as const;

/**
 * Default scopes to request during authentication
 */
export const DEFAULT_SCOPES = [
  OIDC_SCOPES.OPENID,
  OIDC_SCOPES.PROFILE,
  OIDC_SCOPES.EMAIL,
] as const;

/**
 * Claims associated with each scope
 */
export const SCOPE_CLAIMS: Record<string, string[]> = {
  [OIDC_SCOPES.PROFILE]: ['name', 'family_name', 'given_name', 'middle_name', 'nickname', 'preferred_username', 'profile', 'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at'],
  [OIDC_SCOPES.EMAIL]: ['email', 'email_verified'],
  [OIDC_SCOPES.ADDRESS]: ['address'],
  [OIDC_SCOPES.PHONE]: ['phone_number', 'phone_number_verified'],
};

// =============================================================================
// Standard OIDC Parameters
// =============================================================================

/**
 * Standard OAuth 2.0 / OIDC parameter names
 */
export const OIDC_PARAMS = {
  RESPONSE_TYPE: 'response_type',
  CLIENT_ID: 'client_id',
  REDIRECT_URI: 'redirect_uri',
  SCOPE: 'scope',
  STATE: 'state',
  RESPONSE_MODE: 'response_mode',
  NONCE: 'nonce',
  CODE_CHALLENGE: 'code_challenge',
  CODE_CHALLENGE_METHOD: 'code_challenge_method',
  PROMPT: 'prompt',
  DISPLAY: 'display',
  MAX_AGE: 'max_age',
  UI_LOCALES: 'ui_locales',
  ID_TOKEN_HINT: 'id_token_hint',
  LOGIN_HINT: 'login_hint',
  ACR_VALUES: 'acr_values',
  GRANT_TYPE: 'grant_type',
  CODE: 'code',
  ACCESS_TOKEN: 'access_token',
  REFRESH_TOKEN: 'refresh_token',
  ID_TOKEN: 'id_token',
  TOKEN_TYPE: 'token_type',
  EXPIRES_IN: 'expires_in',
} as const;

/**
 * Response type values
 */
export const RESPONSE_TYPES = {
  CODE: 'code',
  ID_TOKEN: 'id_token',
  TOKEN: 'token',
} as const;

/**
 * Response mode values
 */
export const RESPONSE_MODES = {
  QUERY: 'query',
  FRAGMENT: 'fragment',
  FORM_POST: 'form_post',
} as const;

/**
 * Prompt values
 */
export const PROMPT_VALUES = {
  NONE: 'none',
  LOGIN: 'login',
  CONSENT: 'consent',
  SELECT_ACCOUNT: 'select_account',
} as const;

/**
 * Display values
 */
export const DISPLAY_VALUES = {
  PAGE: 'page',
  POPUP: 'popup',
  TOUCH: 'touch',
  WAP: 'wap',
} as const;

/**
 * Grant type values
 */
export const GRANT_TYPES = {
  AUTHORIZATION_CODE: 'authorization_code',
  REFRESH_TOKEN: 'refresh_token',
  CLIENT_CREDENTIALS: 'client_credentials',
  PASSWORD: 'password',
} as const;

/**
 * Token type values
 */
export const TOKEN_TYPES = {
  BEARER: 'Bearer',
} as const;

/**
 * PKCE code challenge methods
 */
export const CODE_CHALLENGE_METHODS = {
  S256: 'S256',
  PLAIN: 'plain',
} as const;

// =============================================================================
// Cookie Configuration
// =============================================================================

/**
 * Cookie names used in the authentication flow
 */
export const COOKIE_NAMES = {
  /**
   * Temporary auth state cookie
   * Stores: code_verifier, state, nonce, timestamp, redirect_uri
   * Duration: 10 minutes
   */
  AUTH_STATE: 'oidc_auth_state',

  /**
   * Session cookie
   * Stores: User data, tokens, expiration
   * Duration: Based on refresh token expiry
   */
  SESSION: 'oidc_session',
} as const;

/**
 * Default cookie configuration
 */
export const COOKIE_CONFIG = {
  // Auth state cookie (temporary)
  AUTH_STATE: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax' as const,
    maxAge: 600, // 10 minutes in seconds
    path: '/',
  },

  // Session cookie (persistent)
  SESSION: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax' as const,
    maxAge: 60 * 60 * 24 * 30, // 30 days in seconds
    path: '/',
  },
} as const;

/**
 * SameSite attribute values
 */
export const SAMESITE_VALUES = {
  STRICT: 'strict',
  LAX: 'lax',
  NONE: 'none',
} as const;

// =============================================================================
// Time Constants
// =============================================================================

/**
 * Time constants used in authentication
 */
export const TIME_CONSTANTS = {
  AUTH_STATE_EXPIRATION: 600, // 10 minutes in seconds
  SESSION_EXPIRATION_DEFAULT: 60 * 60 * 24 * 30, // 30 days in seconds
  TOKEN_REFRESH_WINDOW: 300, // 5 minutes in seconds (refresh before expiry)
  CLOCK_SKEW_TOLERANCE: 60, // 60 seconds in seconds (tolerance for clock skew)
} as const;

// =============================================================================
// Error Codes
// =============================================================================

/**
 * OAuth 2.0 Authorization Error Codes
 *
 * @see https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1
 */
export const AUTHORIZATION_ERROR_CODES = {
  INVALID_REQUEST: 'invalid_request',
  UNAUTHORIZED_CLIENT: 'unauthorized_client',
  ACCESS_DENIED: 'access_denied',
  UNSUPPORTED_RESPONSE_TYPE: 'unsupported_response_type',
  INVALID_SCOPE: 'invalid_scope',
  SERVER_ERROR: 'server_error',
  TEMPORARILY_UNAVAILABLE: 'temporarily_unavailable',
} as const;

/**
 * OAuth 2.0 Token Error Codes
 *
 * @see https://www.rfc-editor.org/rfc/rfc6749#section-5.2
 */
export const TOKEN_ERROR_CODES = {
  INVALID_REQUEST: 'invalid_request',
  INVALID_CLIENT: 'invalid_client',
  INVALID_GRANT: 'invalid_grant',
  UNAUTHORIZED_CLIENT: 'unauthorized_client',
  UNSUPPORTED_GRANT_TYPE: 'unsupported_grant_type',
  INVALID_SCOPE: 'invalid_scope',
} as const;

/**
 * Custom application error codes
 */
export const APP_ERROR_CODES = {
  CONFIGURATION_ERROR: 'configuration_error',
  STATE_MISMATCH: 'state_mismatch',
  STATE_EXPIRED: 'state_expired',
  STATE_MISSING: 'state_missing',
  TOKEN_VALIDATION_ERROR: 'token_validation_error',
  DISCOVERY_ERROR: 'discovery_error',
  SESSION_EXPIRED: 'session_expired',
  SESSION_INVALID: 'session_invalid',
  PROVIDER_ERROR: 'provider_error',
} as const;

/**
 * Error messages for common scenarios
 */
export const ERROR_MESSAGES: Record<string, string> = {
  [APP_ERROR_CODES.STATE_MISMATCH]: 'The state parameter does not match. The authentication request may have been tampered with or expired.',
  [APP_ERROR_CODES.STATE_EXPIRED]: 'The authentication request has expired. Please try again.',
  [APP_ERROR_CODES.STATE_MISSING]: 'The state parameter is missing from the authentication response.',
  [APP_ERROR_CODES.SESSION_EXPIRED]: 'Your session has expired. Please log in again.',
  [APP_ERROR_CODES.SESSION_INVALID]: 'Your session is invalid. Please log in again.',
  [APP_ERROR_CODES.DISCOVERY_ERROR]: 'Failed to discover the OpenID Connect provider configuration. Please check the provider URL.',
  [APP_ERROR_CODES.CONFIGURATION_ERROR]: 'The OIDC configuration is invalid. Please check the environment variables.',

  [AUTHORIZATION_ERROR_CODES.ACCESS_DENIED]: 'You denied access to the application.',
  [AUTHORIZATION_ERROR_CODES.SERVER_ERROR]: 'The authorization server encountered an error. Please try again later.',
  [AUTHORIZATION_ERROR_CODES.TEMPORARILY_UNAVAILABLE]: 'The authorization server is temporarily unavailable. Please try again later.',
  [AUTHORIZATION_ERROR_CODES.UNSUPPORTED_RESPONSE_TYPE]: 'The authorization server does not support the requested response type.',
  [AUTHORIZATION_ERROR_CODES.INVALID_SCOPE]: 'The requested scope is invalid or unsupported.',
  [AUTHORIZATION_ERROR_CODES.UNAUTHORIZED_CLIENT]: 'The client is not authorized to use this authorization grant type.',

  [TOKEN_ERROR_CODES.INVALID_GRANT]: 'The authorization code is invalid or has expired.',
  [TOKEN_ERROR_CODES.INVALID_CLIENT]: 'The client authentication failed.',
} as const;

// =============================================================================
// JWT Validation Constants
// =============================================================================

/**
 * JWT-related constants for token validation
 */
export const JWT_CONSTANTS = {
  /**
   * Required claims that must be present in an ID token
   */
  REQUIRED_CLAIMS: ['iss', 'sub', 'aud', 'exp', 'iat'] as const,

  /**
   * Supported signing algorithms for ID tokens
   * Note: 'none' is intentionally excluded for security
   */
  SUPPORTED_ALGORITHMS: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'HS256', 'HS384', 'HS512'] as const,

  /**
   * Token type header value
   */
  TOKEN_TYPE: 'JWT',
} as const;

// =============================================================================
// Discovery Configuration
// =============================================================================

/**
 * OpenID Connect Discovery endpoint path
 *
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
 */
export const DISCOVERY_PATH = '/.well-known/openid-configuration';

/**
 * JWKS endpoint path (relative to issuer)
 */
export const JWKS_PATH = '/.well-known/jwks.json';

/**
 * Provider metadata cache TTL (in milliseconds)
 * Default: 5 minutes
 */
export const PROVIDER_METADATA_CACHE_TTL = 5 * 60 * 1000;

/**
 * JWKS cache TTL (in milliseconds)
 * Default: 10 minutes (keys rotate less frequently)
 */
export const JWKS_CACHE_TTL = 10 * 60 * 1000;

// =============================================================================
// PKCE Constants
// =============================================================================

/**
 * PKCE (Proof Key for Code Exchange) constants
 *
 * @see https://www.rfc-editor.org/rfc/rfc7636
 */
export const PKCE_CONSTANTS = {
  /**
   * Minimum length of code verifier
   */
  VERIFIER_MIN_LENGTH: 43,

  /**
   * Maximum length of code verifier
   */
  VERIFIER_MAX_LENGTH: 128,

  /**
   * Characters allowed in code verifier
   * Unreserved characters: A-Z, a-z, 0-9, -, ., _, ~
   */
  ALLOWED_CHARS: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~',

  /**
   * Default code challenge method
   */
  DEFAULT_METHOD: 'S256',
} as const;

// =============================================================================
// HTTP Constants
// =============================================================================

/**
 * HTTP-related constants for OIDC requests
 */
export const HTTP_CONSTANTS = {
  /**
   * Request timeout for OIDC provider requests (in milliseconds)
   */
  REQUEST_TIMEOUT: 10000, // 10 seconds

  /**
   * Maximum number of retries for failed requests
   */
  MAX_RETRIES: 3,

  /**
   * Delay between retries (in milliseconds)
   */
  RETRY_DELAY: 1000, // 1 second
} as const;

// =============================================================================
// Route Paths
// =============================================================================

/**
 * Application route paths for authentication
 */
export const ROUTES = {
  LOGIN: '/auth/login',
  CALLBACK: '/auth/callback',
  LOGOUT: '/auth/logout',
  ERROR: '/auth/error',
  USER: '/user',
  HOME: '/',
} as const;

// =============================================================================
// Validation Patterns
// =============================================================================

/**
 * Regular expression patterns for validation
 */
export const VALIDATION_PATTERNS = {
  /**
   * Pattern for validating URLs (http/https)
   */
  URL: /^https?:\/\/.+/,

  /**
   * Pattern for validating email addresses
   */
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,

  /**
   * Pattern for validating UUIDs
   */
  UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
} as const;
