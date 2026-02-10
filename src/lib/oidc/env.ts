/**
 * OIDC Environment Configuration
 *
 * Runtime validation for all required OIDC environment variables.
 * The application will fail fast with a clear error message if
 * any required configuration is missing or invalid.
 */

interface EnvConfig {
  // OIDC Provider Configuration
  issuer: string;
  clientId: string;
  clientSecret: string | undefined;

  // Application URLs
  redirectUri: string;
  postLogoutRedirectUri: string;

  // OAuth/OIDC Settings
  scope: string;

  // Session Security
  sessionSecret: string;

  // Environment
  nodeEnv: string;
  isProduction: boolean;
  isDevelopment: boolean;
}

/**
 * Validates a URL string
 */
function isValidUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Validates the session secret is at least 32 characters
 */
function isValidSessionSecret(secret: string): boolean {
  return secret.length >= 32;
}

/**
 * Validates and returns the OIDC environment configuration
 *
 * @throws {Error} If any required environment variable is missing or invalid
 * @returns Validated environment configuration
 */
function getEnvConfig(): EnvConfig {
  const {
    OIDC_ISSUER,
    OIDC_CLIENT_ID,
    OIDC_CLIENT_SECRET,
    OIDC_REDIRECT_URI,
    OIDC_POST_LOGOUT_REDIRECT_URI,
    OIDC_SCOPE,
    SESSION_SECRET,
    NODE_ENV,
  } = process.env;

  // Validate required environment variables
  const errors: string[] = [];

  // OIDC_ISSUER (required)
  if (!OIDC_ISSUER) {
    errors.push('OIDC_ISSUER is required');
  } else if (!isValidUrl(OIDC_ISSUER)) {
    errors.push('OIDC_ISSUER must be a valid URL');
  }

  // OIDC_CLIENT_ID (required)
  if (!OIDC_CLIENT_ID) {
    errors.push('OIDC_CLIENT_ID is required');
  }

  // OIDC_CLIENT_SECRET (optional for public clients)
  if (OIDC_CLIENT_SECRET !== undefined && OIDC_CLIENT_SECRET.length === 0) {
    // Treat empty string as undefined
    process.env.OIDC_CLIENT_SECRET = undefined;
  }

  // OIDC_REDIRECT_URI (required)
  if (!OIDC_REDIRECT_URI) {
    errors.push('OIDC_REDIRECT_URI is required');
  } else if (!isValidUrl(OIDC_REDIRECT_URI)) {
    errors.push('OIDC_REDIRECT_URI must be a valid URL');
  }

  // OIDC_POST_LOGOUT_REDIRECT_URI (required)
  if (!OIDC_POST_LOGOUT_REDIRECT_URI) {
    errors.push('OIDC_POST_LOGOUT_REDIRECT_URI is required');
  } else if (!isValidUrl(OIDC_POST_LOGOUT_REDIRECT_URI)) {
    errors.push('OIDC_POST_LOGOUT_REDIRECT_URI must be a valid URL');
  }

  // OIDC_SCOPE (required)
  if (!OIDC_SCOPE) {
    errors.push('OIDC_SCOPE is required');
  } else if (!OIDC_SCOPE.includes('openid')) {
    errors.push('OIDC_SCOPE must include "openid"');
  }

  // SESSION_SECRET (required)
  if (!SESSION_SECRET) {
    errors.push('SESSION_SECRET is required');
  } else if (!isValidSessionSecret(SESSION_SECRET)) {
    errors.push('SESSION_SECRET must be at least 32 characters long');
  }

  // NODE_ENV (optional, defaults to development)
  const nodeEnv = NODE_ENV || 'development';
  if (
    nodeEnv !== 'development' &&
    nodeEnv !== 'production' &&
    nodeEnv !== 'test'
  ) {
    errors.push('NODE_ENV must be one of: development, production, test');
  }

  // If there are any validation errors, throw with details
  if (errors.length > 0) {
    throw new Error(
      `Invalid OIDC configuration:\n${errors.map((e) => `  - ${e}`).join('\n')}\n\n` +
        'Please check your .env.local file or environment variables.'
    );
  }

  // Ensure issuer URL has no trailing slash for consistency
  const issuer = OIDC_ISSUER!.replace(/\/$/, '');

  return {
    issuer,
    clientId: OIDC_CLIENT_ID!,
    clientSecret: OIDC_CLIENT_SECRET,
    redirectUri: OIDC_REDIRECT_URI!,
    postLogoutRedirectUri: OIDC_POST_LOGOUT_REDIRECT_URI!,
    scope: OIDC_SCOPE!,
    sessionSecret: SESSION_SECRET!,
    nodeEnv,
    isProduction: nodeEnv === 'production',
    isDevelopment: nodeEnv === 'development',
  };
}

/**
 * Cached environment configuration
 */
let cachedConfig: EnvConfig | null = null;

/**
 * Returns the OIDC environment configuration.
 * Configuration is cached after first validation.
 *
 * @returns Validated environment configuration
 */
export function getConfig(): EnvConfig {
  if (!cachedConfig) {
    cachedConfig = getEnvConfig();
  }
  return cachedConfig;
}

/**
 * Resets the cached configuration (useful for testing)
 */
export function resetConfig(): void {
  cachedConfig = null;
}

// Export the type for use in other modules
export type { EnvConfig };
