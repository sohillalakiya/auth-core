/**
 * OIDC Error Handling
 *
 * Centralized error handling for OAuth 2.0 and OpenID Connect errors.
 * Provides error mapping, user-friendly messages, and logging utilities.
 *
 * @see https://www.rfc-editor.org/rfc6749#section-4.1.2.1
 * @see https://openid.net/specs/openid-connect-core-1_0.html#AuthError
 */

import { AUTHORIZATION_ERROR_CODES, TOKEN_ERROR_CODES, APP_ERROR_CODES, ERROR_MESSAGES } from './constants';

/**
 * Authentication error details
 */
export interface AuthError {
  code: string;
  description: string;
  errorUri?: string;
  status?: number;
}

/**
 * Creates a user-friendly error message from an error code.
 *
 * @param code - The error code
 * @param description - Optional error description
 * @returns User-friendly error message
 */
export function getErrorMessage(code: string, description?: string): string {
  // Check for predefined error messages
  const predefinedMessage = ERROR_MESSAGES[code];
  if (predefinedMessage) {
    return predefinedMessage;
  }

  // Use provided description or generic message
  return description || `An error occurred (code: ${code})`;
}

/**
 * Creates an authentication error object.
 *
 * @param code - The error code
 * @param description - Error description
 * @param errorUri - Optional error URI for more information
 * @returns Auth error object
 */
export function createAuthError(
  code: string,
  description?: string,
  errorUri?: string
): AuthError {
  return {
    code,
    description: getErrorMessage(code, description),
    errorUri,
  };
}

/**
 * Handles an error thrown during authentication flow.
 *
 * Logs the error securely (redacting sensitive data) and returns
 * an error object suitable for display or logging.
 *
 * @param error - The caught error
 * @param context - Additional context about where the error occurred
 * @returns Auth error object
 *
 * @example
 * ```ts
 * try {
 *   await exchangeAuthorizationCode(options);
 * } catch (error) {
 *   const authError = handleAuthError(error, 'token_exchange');
 *   console.error(authError.description);
 * }
 * ```
 */
export function handleAuthError(
  error: unknown,
  context: string = 'authentication'
): AuthError {
  if (error instanceof Error) {
    // Check if it's one of our custom errors
    if ('code' in error && typeof error.code === 'string') {
      return error as unknown as AuthError;
    }

    // Generic error
    return createAuthError(
      APP_ERROR_CODES.PROVIDER_ERROR,
      `${context}: ${error.message}`
    );
  }

  // Unknown error type
  return createAuthError(
    APP_ERROR_CODES.PROVIDER_ERROR,
    `${context}: Unknown error occurred`
  );
}

/**
 * Redacts sensitive information from error messages before logging.
 *
 * @param message - The error message to redact
 * @returns The redacted message
 */
export function redactSensitiveData(message: string): string {
  // Redact potential sensitive data patterns
  const patterns = [
    // Tokens (base64-like strings)
    { pattern: /eyJ[a-zA-Z0-9_-]+\./g, replacement: '[REDACTED_TOKEN]' },
    // Client IDs
    { pattern: /client[_-]?[iI]d["']?\s*[:=]\s*["']?[a-zA-Z0-9._-]+["']?/gi, replacement: 'client_id=[REDACTED]' },
    // Client secrets
    { pattern: /client[_-]?secret["']?\s*[:=]\s*["']?[a-zA-Z0-9._-]+["']?/gi, replacement: 'client_secret=[REDACTED]' },
    // Authorization codes
    { pattern: /code["']?\s*[:=]\s*["']?[a-zA-Z0-9._/+=]+["']?/gi, replacement: 'code=[REDACTED]' },
    // State parameters
    { pattern: /state["']?\s*[:=]\s*["']?[a-zA-Z0-9._/+=]+["']?/gi, replacement: 'state=[REDACTED]' },
    // Nonce parameters
    { pattern: /nonce["']?\s*[:=]\s*["']?[a-zA-Z0-9._/+=]+["']?/gi, replacement: 'nonce=[REDACTED]' },
    // Passwords
    { pattern: /password["']?\s*[:=]\s*["']?.+?["']/gi, replacement: 'password=[REDACTED]' },
    // API keys (common formats)
    { pattern: /['"]?AIza[a-zA-Z0-9_-]{35}['"]?/g, replacement: 'api_key=[REDACTED]' },
    { pattern: /['"]?sk-[a-zA-Z0-9_-]+['"]?/g, replacement: 'api_key=[REDACTED]' },
  ];

  let redacted = message;

  for (const { pattern, replacement } of patterns) {
    redacted = redacted.replace(pattern, replacement);
  }

  return redacted;
}

/**
 * Logs an authentication error securely.
 *
 * Redacts sensitive information before logging and includes context.
 *
 * @param error - The error to log
 * @param context - Additional context
 * @param includeStack - Whether to include stack trace
 *
 * @example
 * ```ts
 * try {
 *   await exchangeAuthorizationCode(options);
 * } catch (error) {
 *   logAuthError(error, 'token_exchange');
 * }
 * ```
 */
export function logAuthError(
  error: unknown,
  context: string = 'authentication',
  includeStack: boolean = false
): void {
  const redactedMessage = redactSensitiveData(
    error instanceof Error ? error.message : String(error)
  );

  console.error(`[${context}]`, redactedMessage);

  if (includeStack && error instanceof Error && error.stack) {
    console.error('Stack trace:', error.stack);
  }
}

/**
 * Maps an error code to an HTTP status code.
 *
 * @param code - The OAuth/OIDC error code
 * @returns Appropriate HTTP status code
 */
export function getHttpStatusForError(code: string): number {
  // Direct checks for specific error codes
  if (code === AUTHORIZATION_ERROR_CODES.UNAUTHORIZED_CLIENT || code === TOKEN_ERROR_CODES.UNAUTHORIZED_CLIENT) {
    return 401;
  }
  if (code === AUTHORIZATION_ERROR_CODES.ACCESS_DENIED) {
    return 403;
  }
  if (code === AUTHORIZATION_ERROR_CODES.TEMPORARILY_UNAVAILABLE) {
    return 503;
  }
  if (code === TOKEN_ERROR_CODES.INVALID_CLIENT) {
    return 401;
  }

  // All other errors default to their appropriate status
  const statusMap: Record<string, number> = {
    // Common errors - default to 400
    'invalid_request': 400,
    'invalid_scope': 400,
    'unsupported_response_type': 400,
    'invalid_grant': 400,
    'unsupported_grant_type': 400,

    // App errors
    [APP_ERROR_CODES.CONFIGURATION_ERROR]: 500,
    [APP_ERROR_CODES.STATE_MISMATCH]: 400,
    [APP_ERROR_CODES.STATE_EXPIRED]: 400,
    [APP_ERROR_CODES.STATE_MISSING]: 400,
    [APP_ERROR_CODES.TOKEN_VALIDATION_ERROR]: 401,
    [APP_ERROR_CODES.DISCOVERY_ERROR]: 502,
    [APP_ERROR_CODES.SESSION_EXPIRED]: 401,
    [APP_ERROR_CODES.SESSION_INVALID]: 401,
    [APP_ERROR_CODES.PROVIDER_ERROR]: 502,

    // Additional common errors
    'server_error': 502,
    'temporarily_unavailable': 503,
  };

  return statusMap[code] || 500;
}

/**
 * Checks if an error is a recoverable error (user can retry).
 *
 * @param code - The error code
 * @returns true if the error is recoverable
 */
export function isRecoverableError(code: string): boolean {
  const recoverableErrors = [
    AUTHORIZATION_ERROR_CODES.TEMPORARILY_UNAVAILABLE,
    'server_error',
    'temporarily_unavailable',
  ];

  return recoverableErrors.includes(code as any);
}

/**
 * Checks if an error is a client error (user action required).
 *
 * @param code - The error code
 * @returns true if the error is a client error
 */
export function isClientError(code: string): boolean {
  const clientErrors = [
    AUTHORIZATION_ERROR_CODES.ACCESS_DENIED,
    AUTHORIZATION_ERROR_CODES.INVALID_REQUEST,
    AUTHORIZATION_ERROR_CODES.INVALID_SCOPE,
    AUTHORIZATION_ERROR_CODES.UNSUPPORTED_RESPONSE_TYPE,
    TOKEN_ERROR_CODES.INVALID_GRANT,
    TOKEN_ERROR_CODES.INVALID_REQUEST,
    TOKEN_ERROR_CODES.INVALID_SCOPE,
  ];

  return clientErrors.some((e) => e === code);
}

/**
 * Formats an error for display on the error page.
 *
 * @param code - The error code
 * @param description - Error description
 * @returns Formatted error object for the error page
 */
export function formatErrorForPage(code: string, description?: string): {
  title: string;
  message: string;
  canRetry: boolean;
  suggestion: string;
} {
  const recoverable = isRecoverableError(code);
  const clientError = isClientError(code);

  let title = 'Authentication Error';
  let message = getErrorMessage(code, description);
  let suggestion = 'Please try again or contact support.';

  if (clientError) {
    if (code === AUTHORIZATION_ERROR_CODES.ACCESS_DENIED) {
      title = 'Access Denied';
      message = description || 'You denied access to the application.';
      suggestion = 'If you want to use this application, please grant the required permissions.';
    }
  } else if (recoverable) {
    suggestion = 'The service is temporarily unavailable. Please try again in a moment.';
  }

  return {
    title,
    message,
    canRetry: recoverable,
    suggestion,
  };
}
