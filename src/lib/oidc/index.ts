/**
 * OIDC Library - Main Entry Point
 *
 * Exports all OIDC authentication functionality.
 */

// Environment & Configuration
export { getConfig, resetConfig, type EnvConfig } from './env';

// Type Definitions
export type {
  OpenIDProviderMetadata,
  TokenResponse,
  TokenRefreshRequest,
  TokenRefreshResponse,
  IDTokenClaims,
  AddressClaim,
  UserInfo,
  PKCECodePair,
  AuthorizationRequestParams,
  AuthorizationResponse,
  AuthorizationErrorCode,
  TokenErrorCode,
  SessionData,
  AuthState,
  JWKS,
  JWK,
  JWTHeader,
  JWTPayload,
  LogoutRequestParams,
} from './types';

// Error Classes
export {
  OIDCError,
  ConfigurationError,
  TokenValidationError,
  StateMismatchError,
  DiscoveryError,
} from './types';

// Constants
export {
  OIDC_SCOPES,
  DEFAULT_SCOPES,
  SCOPE_CLAIMS,
  OIDC_PARAMS,
  RESPONSE_TYPES,
  RESPONSE_MODES,
  PROMPT_VALUES,
  DISPLAY_VALUES,
  GRANT_TYPES,
  TOKEN_TYPES,
  CODE_CHALLENGE_METHODS,
  COOKIE_NAMES,
  COOKIE_CONFIG,
  SAMESITE_VALUES,
  TIME_CONSTANTS,
  AUTHORIZATION_ERROR_CODES,
  TOKEN_ERROR_CODES,
  APP_ERROR_CODES,
  ERROR_MESSAGES,
  JWT_CONSTANTS,
  DISCOVERY_PATH,
  JWKS_PATH,
  PROVIDER_METADATA_CACHE_TTL,
  JWKS_CACHE_TTL,
  PKCE_CONSTANTS,
  HTTP_CONSTANTS,
  ROUTES,
  VALIDATION_PATTERNS,
} from './constants';

// PKCE Implementation
export {
  generateCodeVerifier,
  generateCodeChallenge,
  generateCodeChallengeS256,
  generatePKCECodePair,
  isValidCodeVerifier,
  isCodeChallengeMethodSupported,
  createCodeChallengeForRequest,
  type CodeChallengeMethod,
} from './pkce';

// Provider Discovery
export {
  getDiscoveryUrl,
  fetchProviderMetadata,
  validateProviderMetadata,
  assertSupportsPKCE,
  supportsPKCE,
  supportsScopes,
  supportsResponseType,
  clearProviderMetadataCache,
  clearAllProviderMetadataCache,
  getJwksUrl,
  getAuthorizationEndpoint,
  getTokenEndpoint,
  getUserInfoEndpoint,
  getEndSessionEndpoint,
  getIntrospectionEndpoint,
  discoverProvider,
} from './discovery';

// State & Nonce Management
export {
  generateState,
  generateNonce,
  createAuthState,
  serializeAuthState,
  deserializeAuthState,
  isAuthStateValid,
  validateStateMatch,
} from './state';

// Authorization Request Builder
export {
  buildAuthorizationUrl,
  buildAuthorizationUrlWithReauth,
  validateAuthorizationRequest,
  type AuthorizationRequestOptions,
} from './authorization';

// Cookie Management
export {
  setCookie,
  getCookie,
  deleteCookie,
  hasCookie,
  setAuthStateCookie,
  getAuthStateCookie,
  deleteAuthStateCookie,
  setSessionCookie,
  getSessionCookie,
  deleteSessionCookie,
  hasSession,
  getValidSession,
  type CookieOptions,
} from './cookies';

// Token Exchange
export {
  exchangeAuthorizationCode,
  refreshAccessToken,
  isTokenExpired,
  getTokenExpirationTime,
  isValidTokenResponse,
  TokenExchangeError,
  type TokenRequestOptions,
  type TokenErrorResponse,
  type RefreshTokenRequestOptions,
} from './tokens';

// ID Token Validation
export {
  decodeJWTHeader,
  decodeJWTPayload,
  decodeJWT,
  validateJWTHeader,
  validateRequiredClaims,
  validateIssuer,
  validateAudience,
  validateExpiration,
  validateIssuedAt,
  validateNonce,
  validateAuthTime,
  validateAuthorizedParty,
  verifyJWTSignature,
  validateIDToken,
  type IDTokenValidationResult,
  type IDTokenValidationOptions,
} from './validation';

// Session Management
export {
  getValidSessionWithRefresh,
  refreshSessionTokens,
  isSessionValid,
  shouldRefreshSession,
  getSessionExpirationTime,
  getSessionAge,
  getTimeSinceLastUpdate,
  createSessionData,
  destroySession,
  updateSessionTokens,
  type SessionRefreshResult,
} from './session';

// Logout Management
export {
  buildLogoutUrl,
  createLogoutRequest,
  validateLogoutCallback,
  parseLogoutCallback,
  prepareLogout,
  localLogout,
  type LogoutRequestOptions,
  type LogoutState,
} from './logout';

// UserInfo Endpoint
export {
  fetchUserInfo,
  getUserInfo,
  clearUserInfoCache,
  clearAllUserInfoCache,
  getUserInfoForSession,
  enrichSessionWithUserInfo,
} from './userinfo';
