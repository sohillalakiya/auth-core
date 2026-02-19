/**
 * User Dashboard Page (Protected)
 *
 * Displays user information and provides a logout button.
 * This route is protected by the Next.js proxy.
 *
 * @see https://nextjs.org/docs/app/building-your-application/routing/middleware
 */

import { getSession } from '@/lib/oidc/session';
import { ROUTES } from '@/lib/oidc/constants';

/**
 * User dashboard page component.
 */
export default async function UserPage() {
  const session = await getSession();

  // If no session, the middleware should have redirected
  // This is a fallback for edge cases
  if (!session) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-zinc-50 dark:bg-zinc-900">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-zinc-900 dark:text-zinc-50 mb-4">
            Not Authenticated
          </h1>
          <p className="text-zinc-600 dark:text-zinc-400 mb-6">
            Please log in to access this page.
          </p>
          <a
            href={ROUTES.LOGIN}
            className="inline-block px-6 py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition"
          >
            Go to Login
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-zinc-50 to-zinc-100 dark:from-black dark:to-zinc-900">
      <main className="container mx-auto px-4 py-16 max-w-4xl">
        {/* Header */}
        <div className="flex items-center justify-between mb-12">
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-zinc-50">
              User Dashboard
            </h1>
            <p className="text-zinc-600 dark:text-zinc-400 mt-1">
              Welcome back, {session.name}
            </p>
          </div>

          <a
            href={ROUTES.LOGOUT}
            className="inline-flex items-center gap-2 px-4 py-2 bg-red-600 text-white font-medium rounded-lg hover:bg-red-700 transition"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4 4m4 4H7m6 0v4a1 1 0 011-1V7a1 1 0 011-1V3a1 1 0 011-1h1a1 1 0 011 1v3a1 1 0 001 1h6a1 1 0 001-1v-3a1 1 0 011-1V4a1 1 0 011-1h1a1 1 0 011 1v16a1 1 0 001 1h4a1 1 0 001-1v-3m-6 0H7m6 0v4m0-6V4m0 6h6m-6 0h6" />
            </svg>
            Logout
          </a>
        </div>

        {/* User Info Card */}
        <div className="bg-white dark:bg-zinc-800 rounded-2xl shadow-lg overflow-hidden mb-8 border border-zinc-200 dark:border-zinc-700">
          <div className="p-6 border-b border-zinc-200 dark:border-zinc-700">
            <h2 className="text-xl font-semibold text-zinc-900 dark:text-zinc-50">
              Profile Information
            </h2>
          </div>

          <div className="p-6 space-y-4">
            {/* Avatar */}
            <div className="flex items-center gap-4">
              {session.picture ? (
                <img
                  src={session.picture}
                  alt={session.name}
                  className="w-16 h-16 rounded-full object-cover border-2 border-zinc-200 dark:border-zinc-700"
                />
              ) : (
                <div className="w-16 h-16 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white text-xl font-bold">
                  {session.name.charAt(0).toUpperCase()}
                </div>
              )}
              <div>
                <h3 className="text-lg font-medium text-zinc-900 dark:text-zinc-50">
                  {session.name}
                </h3>
                <p className="text-sm text-zinc-500 dark:text-zinc-400">
                  {session.email}
                </p>
              </div>
            </div>

            {/* User Details */}
            <div className="grid gap-4 pt-4 border-t border-zinc-200 dark:border-zinc-700">
              <div>
                <span className="text-sm text-zinc-500 dark:text-zinc-400">User ID</span>
                <p className="text-sm font-mono text-zinc-900 dark:text-zinc-50 break-all mt-1">
                  {session.sub}
                </p>
              </div>

              <div>
                <span className="text-sm text-zinc-500 dark:text-zinc-400">Provider</span>
                <p className="text-sm text-zinc-900 dark:text-zinc-50 mt-1">
                  {session.provider}
                </p>
              </div>

              <div>
                <span className="text-sm text-zinc-500 dark:text-zinc-400">Session Created</span>
                <p className="text-sm text-zinc-900 dark:text-zinc-50 mt-1">
                  {new Date(session.created_at).toLocaleString()}
                </p>
              </div>

              <div>
                <span className="text-sm text-zinc-500 dark:text-zinc-400">Token Expires</span>
                <p className="text-sm text-zinc-900 dark:text-zinc-50 mt-1">
                  {new Date(session.expires_at).toLocaleString()}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Session Info Card */}
        <div className="bg-white dark:bg-zinc-800 rounded-2xl shadow-lg p-6 border border-zinc-200 dark:border-zinc-700">
          <h2 className="text-xl font-semibold text-zinc-900 dark:text-zinc-50 mb-4">
            Session Details
          </h2>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between py-2 border-b border-zinc-100 dark:border-zinc-700">
              <span className="text-zinc-600 dark:text-zinc-400">Access Token</span>
              <span className="font-mono text-zinc-500 dark:text-zinc-500">
                {session.access_token.substring(0, 20)}...
              </span>
            </div>
            {session.refresh_token && (
              <div className="flex justify-between py-2 border-b border-zinc-100 dark:border-zinc-700">
                <span className="text-zinc-600 dark:text-zinc-400">Refresh Token</span>
                <span className="font-mono text-zinc-500 dark:text-zinc-500">
                  {session.refresh_token.substring(0, 20)}...
                </span>
              </div>
            )}
            <div className="flex justify-between py-2">
              <span className="text-zinc-600 dark:text-zinc-400">ID Token</span>
              <span className="font-mono text-zinc-500 dark:text-zinc-500">
                {session.id_token.substring(0, 20)}...
              </span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <footer className="mt-8 text-center text-sm text-zinc-500 dark:text-zinc-500">
          <a href={ROUTES.HOME} className="hover:text-zinc-700 dark:hover:text-zinc-300 transition">
            ← Back to Home
          </a>
        </footer>
      </main>
    </div>
  );
}
