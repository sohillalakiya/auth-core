// Project phases status
const phases = [
  { phase: 1, name: 'Core Configuration & Setup', status: 'complete' },
  { phase: 2, name: 'PKCE Implementation (RFC 7636)', status: 'complete' },
  { phase: 3, name: 'OIDC Provider Discovery & JWKS', status: 'complete' },
  { phase: 4, name: 'Authorization Flow', status: 'complete' },
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
