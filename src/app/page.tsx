import Link from 'next/link';

// Project phases status
const phases = [
  { phase: 1, name: 'Core Configuration & Setup', status: 'complete' },
  { phase: 2, name: 'PKCE Implementation (RFC 7636)', status: 'complete' },
  { phase: 3, name: 'OIDC Provider Discovery & JWKS', status: 'complete' },
  { phase: 4, name: 'Authorization Flow', status: 'pending' },
  { phase: 5, name: 'Callback Handler', status: 'pending' },
  { phase: 6, name: 'ID Token Validation', status: 'pending' },
  { phase: 7, name: 'Session Management', status: 'pending' },
  { phase: 8, name: 'Protected Routes & Middleware', status: 'pending' },
  { phase: 9, name: 'Logout Implementation', status: 'pending' },
  { phase: 10, name: 'UserInfo Endpoint', status: 'pending' },
  { phase: 11, name: 'Error Handling', status: 'pending' },
  { phase: 12, name: 'Security Considerations', status: 'pending' },
  { phase: 13, name: 'Next.js 16 Best Practices', status: 'pending' },
  { phase: 14, name: 'Pages Implementation', status: 'pending' },
  { phase: 15, name: 'Testing Strategy', status: 'pending' },
] as const;

const completedPhases = phases.filter((p) => p.status === 'complete').length;
const totalPhases = phases.length;
const progressPercent = Math.round((completedPhases / totalPhases) * 100);

export default function Home() {
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

        {/* Progress Overview Card */}
        <div className="bg-white dark:bg-zinc-800 rounded-2xl shadow-lg p-8 mb-8 border border-zinc-200 dark:border-zinc-700">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-semibold text-zinc-900 dark:text-zinc-50">
              Implementation Progress
            </h2>
            <span className="text-3xl font-bold text-emerald-600 dark:text-emerald-400">
              {progressPercent}%
            </span>
          </div>

          {/* Progress Bar */}
          <div className="w-full bg-zinc-200 dark:bg-zinc-700 rounded-full h-4 mb-4 overflow-hidden">
            <div
              className="bg-gradient-to-r from-emerald-500 to-emerald-600 h-full rounded-full transition-all duration-500 ease-out"
              style={{ width: `${progressPercent}%` }}
            />
          </div>

          <p className="text-sm text-zinc-600 dark:text-zinc-400">
            {completedPhases} of {totalPhases} phases completed
          </p>
        </div>

        {/* Phases Grid */}
        <div className="grid gap-4 md:grid-cols-2">
          {phases.map((phase) => (
            <div
              key={phase.phase}
              className={`flex items-start gap-4 p-4 rounded-xl border transition-all ${
                phase.status === 'complete'
                  ? 'bg-emerald-50 dark:bg-emerald-900/20 border-emerald-200 dark:border-emerald-800'
                  : 'bg-white dark:bg-zinc-800 border-zinc-200 dark:border-zinc-700'
              }`}
            >
              <div
                className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold ${
                  phase.status === 'complete'
                    ? 'bg-emerald-500 text-white'
                    : 'bg-zinc-200 dark:bg-zinc-700 text-zinc-500 dark:text-zinc-400'
                }`}
              >
                {phase.status === 'complete' ? (
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
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
                        : 'bg-zinc-100 text-zinc-600 dark:bg-zinc-700 dark:text-zinc-400'
                    }`}
                  >
                    {phase.status === 'complete' ? 'Completed' : 'Pending'}
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
              {completedPhases}
            </div>
            <div className="text-sm text-zinc-600 dark:text-zinc-400">Completed</div>
          </div>
          <div className="bg-white dark:bg-zinc-800 rounded-xl p-6 text-center border border-zinc-200 dark:border-zinc-700">
            <div className="text-3xl font-bold text-amber-600 dark:text-amber-400 mb-1">
              {totalPhases - completedPhases}
            </div>
            <div className="text-sm text-zinc-600 dark:text-zinc-400">Remaining</div>
          </div>
          <div className="bg-white dark:bg-zinc-800 rounded-xl p-6 text-center border border-zinc-200 dark:border-zinc-700">
            <div className="text-3xl font-bold text-blue-600 dark:text-blue-400 mb-1">
              6
            </div>
            <div className="text-sm text-zinc-600 dark:text-zinc-400">Files Created</div>
          </div>
        </div>

        {/* Links */}
        <div className="mt-8 flex justify-center gap-4">
          <Link
            href="/docs/OIDC_AUTHENTICATION.md"
            className="inline-flex items-center gap-2 px-6 py-3 bg-zinc-900 dark:bg-zinc-100 text-white dark:text-zinc-900 rounded-full font-medium hover:bg-zinc-800 dark:hover:bg-zinc-200 transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            View Documentation
          </Link>
          <a
            href="https://github.com/anthropics/claude-code"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-6 py-3 border border-zinc-300 dark:border-zinc-600 text-zinc-700 dark:text-zinc-300 rounded-full font-medium hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
          >
            <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
            </svg>
            GitHub
          </a>
        </div>

        {/* Footer */}
        <footer className="mt-16 text-center text-sm text-zinc-500 dark:text-zinc-500">
          Built with Next.js 16, TypeScript, and Tailwind CSS
        </footer>
      </main>
    </div>
  );
}
