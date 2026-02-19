/**
 * Authentication Error Page
 *
 * Displays user-friendly error messages when authentication fails.
 * Shows appropriate actions based on the error type.
 *
 * @see https://nextjs.org/docs/app/building-your-application/routing/pages-and-layouts
 */

import { ROUTES } from '@/lib/oidc/constants';

/**
 * Authentication error page component.
 *
 * Query Parameters:
 * - code: Error code
 * - error: Alternative error parameter
 * - description: Error description
 * - error_uri: URI with more information
 *
 * @example
 * ```tsx
 * // Redirect to error page
 * redirect('/auth/error?code=access_denied&description=User denied access');
 * ```
 */
export default function AuthErrorPage({
  searchParams,
}: {
  searchParams: { code?: string; error?: string; description?: string; error_uri?: string };
}) {
  // Get error code from query params (prefer 'code', fallback to 'error')
  const errorCode = searchParams.code || searchParams.error || 'unknown_error';
  const errorDescription = searchParams.description || 'An unknown error occurred.';
  const errorUri = searchParams.error_uri;

  // Format the error for display
  const error = formatErrorForDisplay(errorCode, errorDescription);

  return (
    <div className="min-h-screen bg-gradient-to-br from-zinc-50 to-zinc-100 dark:from-black dark:to-zinc-900 flex items-center justify-center p-4">
      <div className="max-w-md w-full">
        {/* Error Card */}
        <div className="bg-white dark:bg-zinc-800 rounded-2xl shadow-xl border border-zinc-200 dark:border-zinc-700 overflow-hidden">
          {/* Error Icon */}
          <div className="bg-red-50 dark:bg-red-900/20 p-6 flex justify-center">
            <div className="w-16 h-16 bg-red-100 dark:bg-red-900/30 rounded-full flex items-center justify-center">
              <svg
                className="w-8 h-8 text-red-600 dark:text-red-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                />
              </svg>
            </div>
          </div>

          {/* Error Content */}
          <div className="p-6">
            <h1 className="text-2xl font-bold text-zinc-900 dark:text-zinc-50 mb-2 text-center">
              {error.title}
            </h1>

            <p className="text-zinc-600 dark:text-zinc-400 mb-6 text-center">
              {error.message}
            </p>

            <div className="bg-zinc-50 dark:bg-zinc-900/50 rounded-lg p-4 mb-6">
              <p className="text-sm text-zinc-600 dark:text-zinc-400">
                <span className="font-semibold">Suggestion:</span> {error.suggestion}
              </p>
            </div>

            {/* Error Code Display */}
            {errorCode && errorCode !== 'unknown_error' && (
              <div className="text-xs text-zinc-500 dark:text-zinc-500 mb-6 text-center font-mono">
                Error code: {errorCode}
              </div>
            )}

            {/* Action Buttons */}
            <div className="space-y-3">
              {error.canRetry && (
                <a
                  href={ROUTES.LOGIN}
                  className="block w-full py-3 px-4 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition text-center"
                >
                  Try Again
                </a>
              )}

              <a
                href={ROUTES.HOME}
                className="block w-full py-3 px-4 bg-zinc-200 dark:bg-zinc-700 text-zinc-700 dark:text-zinc-300 font-medium rounded-lg hover:bg-zinc-300 dark:hover:bg-zinc-600 transition text-center"
              >
                Go to Homepage
              </a>
            </div>

            {/* Error URI Link */}
            {errorUri && (
              <div className="mt-6 text-center">
                <a
                  href={errorUri}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-blue-600 dark:text-blue-400 hover:underline"
                >
                  More information about this error
                </a>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-sm text-zinc-500 dark:text-zinc-500 mt-6">
          If this problem persists, please contact support.
        </p>
      </div>
    </div>
  );
}

/**
 * Formats an error code and description for display.
 */
function formatErrorForDisplay(code: string, description: string): {
  title: string;
  message: string;
  canRetry: boolean;
  suggestion: string;
} {
  const recoverableErrors = ['temporarily_unavailable', 'server_error'];
  const clientErrors = ['access_denied', 'invalid_request', 'invalid_scope'];
  const authErrors = ['state_mismatch', 'state_expired', 'token_validation_error'];

  const canRetry = recoverableErrors.includes(code);
  const isClientError = clientErrors.includes(code) || authErrors.includes(code);

  let title = 'Authentication Error';
  let message = description;
  let suggestion = 'Please try again or contact support.';

  if (code === 'access_denied') {
    title = 'Access Denied';
    suggestion =
      'You denied access to the application. If you want to use this application, please grant the required permissions and try again.';
  } else if (code === 'state_mismatch' || code === 'state_expired') {
    title = 'Session Expired';
    message = 'Your authentication session has expired.';
    suggestion = 'Please start the authentication process again.';
  } else if (code === 'token_validation_error') {
    title = 'Token Validation Failed';
    message = 'We could not validate your authentication token.';
    suggestion = 'Please log in again to continue.';
  } else if (code === 'state_missing') {
    title = 'Invalid Request';
    message = 'The authentication request was malformed.';
    suggestion = 'Please try starting from the login page again.';
  } else if (code === 'temporarily_unavailable' || code === 'server_error') {
    title = 'Service Unavailable';
    suggestion = 'The authentication service is temporarily unavailable. Please try again in a moment.';
  } else if (code === 'invalid_grant' || code === 'token_error') {
    title = 'Authentication Failed';
    message = description || 'The authentication token was invalid or expired.';
    suggestion = 'Please log in again.';
  }

  return { title, message, canRetry, suggestion };
}
