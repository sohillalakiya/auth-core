/**
 * OIDC Type Definitions
 *
 * TypeScript interfaces and types for OpenID Connect authentication.
 * These types align with the OpenID Connect Core 1.0 specification.
 */

// =============================================================================
// OpenID Provider Metadata (Discovery 1.0)
// =============================================================================

/**
 * OpenID Provider Metadata
 *
 * Retrieved from the provider's .well-known/openid-configuration endpoint.
 * Based on OpenID Connect Discovery 1.0 specification.
 *
 * @see https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
 */
export interface OpenIDProviderMetadata {
  // Required fields
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  response_types_supported: string[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
  scopes_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];

  // Optional but commonly used fields
  userinfo_endpoint?: string;
  registration_endpoint?: string;
  end_session_endpoint?: string;
  response_modes_supported?: string[];
  grant_types_supported?: string[];
  acr_values_supported?: string[];
  claim_types_supported?: string[];
  claims_supported?: string[];
  claim_parameter_supported?: boolean;
  request_parameter_supported?: boolean;
  request_uri_parameter_supported?: boolean;
  require_request_uri_registration?: boolean;
  frontchannel_logout_supported?: boolean;
  frontchannel_logout_session_supported?: boolean;
  backchannel_logout_supported?: boolean;
  backchannel_logout_session_supported?: boolean;
  tls_client_certificate_bound_access_tokens?: boolean;
  revocation_endpoint?: string;
  introspection_endpoint?: string;
  pushed_authorization_request_endpoint?: string;
  mtls_endpoint_aliases?: MTLSEndpointAliases;
  code_challenge_methods_supported?: string[];
  authorization_signing_alg_values_supported?: string[];
  authorization_encryption_alg_values_supported?: string[];
  authorization_encryption_enc_values_supported?: string[];
  id_token_encryption_alg_values_supported?: string[];
  id_token_encryption_enc_values_supported?: string[];
  userinfo_signing_alg_values_supported?: string[];
  userinfo_encryption_alg_values_supported?: string[];
  userinfo_encryption_enc_values_supported?: string[];
  request_object_signing_alg_values_supported?: string[];
  request_object_encryption_alg_values_supported?: string[];
  request_object_encryption_enc_values_supported?: string[];
  token_endpoint_auth_signing_alg_values_supported?: string[];
  display_values_supported?: string[];
  claims_locales_supported?: string[];
  ui_locales_supported?: string[];
  op_policy_uri?: string;
  op_tos_uri?: string;
  service_documentation?: string;
}

/**
 * Mutual TLS Endpoint Aliases
 */
export interface MTLSEndpointAliases {
  token_endpoint?: string;
  revocation_endpoint?: string;
  introspection_endpoint?: string;
  pushed_authorization_request_endpoint?: string;
  device_authorization_endpoint?: string;
  registration_endpoint?: string;
}

// =============================================================================
// Token Types
// =============================================================================

/**
 * Token Response
 *
 * Response from the token endpoint when exchanging an authorization code.
 * Based on RFC 6749 Section 4.1.4 and OpenID Connect Core 1.0 Section 3.1.3.3
 *
 * @see https://www.rfc-editor.org/rfc/rfc6749#section-4.1.4
 */
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token: string;
  scope?: string;
}

/**
 * Token Refresh Request
 *
 * Request payload for refreshing an access token.
 */
export interface TokenRefreshRequest {
  grant_type: 'refresh_token';
  refresh_token: string;
  client_id?: string;
  client_secret?: string;
  scope?: string;
}

/**
 * Token Refresh Response
 *
 * Response from token refresh request.
 */
export interface TokenRefreshResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
}

/**
 * ID Token Claims
 *
 * Standard claims from the ID token as defined in OpenID Connect Core 1.0.
 * The ID token is a JWT that contains claims about the authentication event.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#IDToken
 */
export interface IDTokenClaims {
  // Required claims
  iss: string; // Issuer identifier
  sub: string; // Subject identifier (unique user ID)
  aud: string | string[]; // Audience(s)
  exp: number; // Expiration time
  iat: number; // Issued at time

  // Conditional claims
  auth_time?: number; // Time when authentication occurred
  nonce?: string; // String value used to associate a Client session with an ID Token
  acr?: string; // Authentication Context Class Reference
  amr?: string[]; // Authentication Methods References
  azp?: string; // Authorized party
  at_hash?: string; // Access token hash
  c_hash?: string; // Code hash

  // Standard user claims (may be included)
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  email?: string;
  email_verified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: AddressClaim;
  updated_at?: number;
}

/**
 * Address Claim
 *
 * Standard address claim as defined in OpenID Connect.
 */
export interface AddressClaim {
  formatted?: string;
  street_address?: string;
  locality?: string;
  region?: string;
  postal_code?: string;
  country?: string;
}

// =============================================================================
// UserInfo Types
// =============================================================================

/**
 * UserInfo Response
 *
 * Response from the UserInfo endpoint.
 * Contains claims about the authenticated user.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
 */
export interface UserInfo {
  sub: string; // Required - Subject identifier
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  email?: string;
  email_verified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: AddressClaim;
  updated_at?: number;
}

// =============================================================================
// PKCE Types (RFC 7636)
// =============================================================================

/**
 * PKCE Verifier and Challenge
 *
 * Contains the code verifier and generated challenge for PKCE flow.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7636
 */
export interface PKCECodePair {
  code_verifier: string;
  code_challenge: string;
  code_challenge_method: 'S256';
}

/**
 * Valid PKCE code challenge methods
 */
export type CodeChallengeMethod = 'S256' | 'plain';

// =============================================================================
// Authorization Types
// =============================================================================

/**
 * Authorization Request Parameters
 *
 * Parameters sent to the authorization endpoint.
 */
export interface AuthorizationRequestParams {
  response_type: 'code';
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  response_mode?: 'query' | 'fragment' | 'form_post';
  nonce?: string;
  code_challenge: string;
  code_challenge_method: CodeChallengeMethod;
  prompt?: 'none' | 'login' | 'consent' | 'select_account';
  display?: 'page' | 'popup' | 'touch' | 'wap';
  max_age?: number;
  ui_locales?: string;
  id_token_hint?: string;
  login_hint?: string;
  acr_values?: string;
}

/**
 * Authorization Response
 *
 * Parameters received from the authorization callback.
 */
export interface AuthorizationResponse {
  code: string;
  state: string;
  error?: string;
  error_description?: string;
  error_uri?: string;
}

/**
 * Authorization Error Codes
 *
 * Standard OAuth 2.0 error codes for authorization errors.
 *
 * @see https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1
 */
export type AuthorizationErrorCode =
  | 'invalid_request'
  | 'unauthorized_client'
  | 'access_denied'
  | 'unsupported_response_type'
  | 'invalid_scope'
  | 'server_error'
  | 'temporarily_unavailable';

// =============================================================================
// Token Error Types
// =============================================================================

/**
 * Token Error Codes
 *
 * Standard OAuth 2.0 error codes for token endpoint errors.
 *
 * @see https://www.rfc-editor.org/rfc/rfc6749#section-5.2
 */
export type TokenErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'invalid_scope';

// =============================================================================
// Session Types
// =============================================================================

/**
 * Session Data
 *
 * Data stored in the encrypted session cookie.
 */
export interface SessionData {
  // User identifiers
  sub: string; // Subject (user ID)
  name: string;
  email: string;
  picture?: string;

  // Tokens
  access_token: string;
  refresh_token?: string;
  expires_at: number; // Access token expiration timestamp

  // ID Token (for logout)
  id_token: string;

  // Metadata
  provider: string; // Issuer identifier
  created_at: number; // Session creation timestamp
  updated_at: number; // Last update timestamp
}

/**
 * Auth State (Temporary)
 *
 * Data stored in the temporary cookie during the auth flow.
 */
export interface AuthState {
  code_verifier: string;
  state: string;
  nonce: string;
  timestamp: number;
  redirect_uri: string;
}

// =============================================================================
// JWKS Types
// =============================================================================

/**
 * JSON Web Key Set
 *
 * Set of public keys for verifying JWT signatures.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7517
 */
export interface JWKS {
  keys: JWK[];
}

/**
 * JSON Web Key
 *
 * Public key for JWT signature verification.
 */
export interface JWK {
  kty: string; // Key Type (e.g., "RSA")
  use?: string; // Public Key Use (e.g., "sig")
  key_ops?: string[]; // Key Operations
  alg?: string; // Algorithm (e.g., "RS256")
  kid?: string; // Key ID
  n?: string; // Modulus (for RSA)
  e?: string; // Exponent (for RSA)
  x?: string; // X coordinate (for EC)
  y?: string; // Y coordinate (for EC)
  crv?: string; // Curve (for EC)
  k?: string; // Key value (for symmetric)
}

/**
 * JWT Header
 *
 * JOSE header of a JWT.
 */
export interface JWTHeader {
  alg: string;
  typ?: string;
  cty?: string;
  kid?: string;
  jku?: string;
  jwk?: JWK;
  x5u?: string;
  x5c?: string[];
  x5t?: string;
  'x5t#S256'?: string;
}

/**
 * JWT Payload (generic)
 *
 * Generic JWT payload with standard claims.
 */
export interface JWTPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [key: string]: unknown;
}

// =============================================================================
// Logout Types
// =============================================================================

/**
 * RP-Initiated Logout Request
 *
 * Parameters for the logout endpoint.
 *
 * @see https://openid.net/specs/openid-connect-rpinitiated-1_0.html
 */
export interface LogoutRequestParams {
  id_token_hint: string;
  post_logout_redirect_uri?: string;
  state?: string;
}

// =============================================================================
// Custom Error Types
// =============================================================================

/**
 * OIDC Error
 *
 * Base error class for OIDC-related errors.
 */
export class OIDCError extends Error {
  constructor(
    message: string,
    public code?: string,
    public description?: string
  ) {
    super(message);
    this.name = 'OIDCError';
  }
}

/**
 * Configuration Error
 *
 * Error thrown when OIDC configuration is invalid.
 */
export class ConfigurationError extends OIDCError {
  constructor(message: string) {
    super(message, 'configuration_error');
    this.name = 'ConfigurationError';
  }
}

/**
 * Token Validation Error
 *
 * Error thrown when token validation fails.
 */
export class TokenValidationError extends OIDCError {
  constructor(message: string, public claim?: string) {
    super(message, 'token_validation_error');
    this.name = 'TokenValidationError';
  }
}

/**
 * State Mismatch Error
 *
 * Error thrown when state parameter doesn't match.
 */
export class StateMismatchError extends OIDCError {
  constructor(message: string) {
    super(message, 'state_mismatch');
    this.name = 'StateMismatchError';
  }
}

/**
 * Discovery Error
 *
 * Error thrown when provider discovery fails.
 */
export class DiscoveryError extends OIDCError {
  constructor(message: string) {
    super(message, 'discovery_error');
    this.name = 'DiscoveryError';
  }
}
