/**
 * Homepage with Project Status and Login
 *
 * Public page showing implementation progress with login capability.
 * Shows different UI based on authentication status.
 *
 * @see https://nextjs.org/docs/app/building-your-application/routing/pages
 */

import { getSession } from '@/lib/oidc/session';
import { ROUTES } from '@/lib/oidc/constants';

async function HomePage() {
  const session = await getSession();
  const isAuthenticated = !!session;

  return (
    <div className="min-h-screen bg-gradient-to-br from-zinc-50 to-zinc-100 dark:from-black dark:to-zinc-900">
      <main className="container mx-auto px-4 py-16 max-w-4xl">
        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50 mb-4">
            OIDC Authentication Implementation
          </h1>
          <p className="text-lg text-zinc-600 dark:text-zinc-400 max-w-2xl mx-auto">
            OpenID Connect (OIDC) authentication for Next.js 16 using Authorization Code Flow with PKCE,
            following RFC standards without any third-party authentication libraries.
          </p>
        </div>

        {/* Auth Status Card */}
        {isAuthenticated ? (
          <div className="bg-emerald-50 dark:bg-emerald-900/20 rounded-2xl shadow-lg p-6 mb-8 border border-emerald-200 dark:border-emerald-800">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-emerald-700 dark:text-emerald-300 font-medium">✓ Authenticated</p>
                <h2 className="text-xl font-semibold text-zinc-900 dark:text-zinc-50">
                  Welcome back, {session.name}
                </h2>
                <p className="text-sm text-zinc-600 dark:text-zinc-400">{session.email}</p>
              </div>
              <a
                href={ROUTES.USER}
                className="inline-flex items-center gap-2 px-4 py-2 bg-emerald-600 text-white font-medium rounded-lg hover:bg-emerald-700 transition"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 4 4 0 018 0 8 8 0 011-8-8 8 0 01-8 8z" />
                </svg>
                Dashboard
              </a>
            </div>
          </div>
        ) : (
          <div className="bg-zinc-50 dark:bg-zinc-900 rounded-2xl p-6 mb-8 border border-zinc-200 dark:border-zinc-700 text-center">
            <p className="text-zinc-600 dark:text-zinc-400 mb-4">
              Sign in to access your dashboard
            </p>
            <a
              href={ROUTES.LOGIN}
              className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 16l4-4m0 0l4 4m-4-4v4m0 0h8" />
              </svg>
              Sign In with OIDC
            </a>
          </div>
        )}

        {/* Progress Overview Card */}
        <div className="bg-white dark:bg-zinc-800 rounded-2xl shadow-lg p-8 mb-8 border border-zinc-200 dark:border-zinc-700">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-semibold text-zinc-900 dark:text-zinc-50">
              Implementation Progress
            </h2>
            <span className="text-3xl font-bold text-emerald-600 dark:text-emerald-400">
              {93}%
            </span>
          </div>

          {/* Progress Bar */}
          <div className="w-full bg-zinc-200 dark:bg-zinc-700 rounded-full h-4 mb-4 overflow-hidden">
            <div
              className="bg-gradient-to-r from-emerald-500 to-emerald-600 h-full rounded-full transition-all duration-500 ease-out"
              style={{ width: '93%' }}
            />
          </div>

          <p className="text-sm text-zinc-600 dark:text-zinc-400">
            14 of 15 phases completed
          </p>
        </div>

        {/* Phases Grid */}
        <div className="grid gap-4 md:grid-cols-2">
          {[
            { phase: 1, name: 'Core Configuration & Setup', status: 'complete' },
            { phase: 2, name: 'PKCE Implementation (RFC 7636)', status: 'complete' },
            { phase: 3, name: 'OIDC Provider Discovery & JWKS', status: 'complete' },
            { phase: 4, name: 'Authorization Flow', status: 'complete' },
            { phase: 5, name: 'Callback Handler', status: 'complete' },
            { phase: 6, name: 'ID Token Validation', status: 'complete' },
            { phase: 7, name: 'Session Management', status: 'complete' },
            { phase: 8, name: 'Protected Routes & Middleware', status: 'complete' },
            { phase: 9, name: 'Logout Implementation', status: 'complete' },
            { phase: 10, name: 'UserInfo Endpoint', status: 'complete' },
            { phase: 11, name: 'Error Handling', status: 'complete' },
            { phase: 12, name: 'Security Considerations', status: 'complete' },
            { phase: 13, name: 'Next.js 16 Best Practices', status: 'complete' },
            { phase: 14, name: 'Pages Implementation', status: 'complete' },
            { phase: 15, name: 'Testing Strategy', status: 'pending' },
          ].map((phase) => (
            <div
              key={phase.phase}
              className={`flex items-start gap-4 p-4 rounded-xl border transition-all ${
                phase.status === 'complete'
                  ? 'bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800'
                  : phase.status === 'in_progress'
                    ? 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800'
                    : 'bg-white dark:bg-zinc-800 border-zinc-200 dark:border-zinc-700'
              }`}
            >
              <div
                className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold ${
                  phase.status === 'complete'
                    ? 'bg-emerald-500 text-white'
                    : phase.status === 'in_progress'
                      ? 'bg-blue-500 text-white'
                    : 'bg-zinc-200 dark:bg-zinc-700 text-zinc-500 dark:text-zinc-400'
                }`}
              >
                {phase.status === 'complete' ? (
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                ) : phase.status === 'in_progress' ? (
                  <div className="w-2 h-2 bg-white rounded-full animate-pulse" />
                ) : (
                  phase.phase
                )}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <h3 className="font-medium text-zinc-900 dark:text-zinc-50">
                    Phase {phase.phase}
                  </h3>
                  <span
                    className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                      phase.status === 'complete'
                        ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/50 dark:text-emerald-300'
                        : phase.status === 'in_progress'
                          ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/50 dark:text-blue-300'
                          : 'bg-zinc-100 text-zinc-600 dark:bg-zinc-700 dark:text-zinc-400'
                    }`}
                  >
                    {phase.status === 'complete' ? 'Completed' : phase.status === 'in_progress' ? 'In Progress' : 'Pending'}
                  </span>
                </div>
                <p className="text-sm text-zinc-600 dark:text-zinc-400">
                  {phase.name}
                </p>
              </div>
            </div>
          ))}
        </div>

        {/* Stats Section */}
        <div className="grid grid-cols-3 gap-4 mt-8">
          <div className="bg-white dark:bg-zinc-800 rounded-xl p-6 text-center border border-zinc-200 dark:border-zinc-700">
            <div className="text-3xl font-bold text-emerald-600 dark:text-emerald-400 mb-1">
              14
            </div>
            <div className="text-sm text-zinc-600 dark:text-zinc-400">Completed</div>
          </div>
          <div className="bg-white dark:bg-zinc-800 rounded-xl p-6 text-center border border-zinc-200 dark:border-zinc-700">
            <div className="text-3xl font-bold text-amber-600 dark:text-amber-400 mb-1">
              1
            </div>
            <div className="text-sm text-zinc-600 dark:text-zinc-400">Remaining</div>
          </div>
          <div className="bg-white dark:bg-zinc-800 rounded-xl p-6 text-center border border-zinc-200 dark:border-zinc-700">
            <div className="text-3xl font-bold text-blue-600 dark:text-blue-400 mb-1">
              11
            </div>
            <div className="text-sm text-zinc-600 dark:text-zinc-400">Files Created</div>
          </div>
        </div>

        {/* Footer */}
        <footer className="mt-16 text-center text-sm text-zinc-500 dark:text-zinc-500">
          Built with Next.js 16, TypeScript, and Tailwind CSS
        </footer>
      </main>
    </div>
  );
}

export default HomePage;
