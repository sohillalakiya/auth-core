import Image from 'next/image';
import { redirect } from 'next/navigation';
import { getSession } from '@/lib/oidc/session';
import { ROUTES } from '@/lib/oidc/constants';

export default async function HomePage() {
  const session = await getSession();

  if (!session) {
    redirect('/login');
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

          <div className="flex items-center gap-2">
            <a
              href="/todos"
              className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 transition text-sm"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
              </svg>
              Todo List
            </a>
            <a
              href={ROUTES.LOGOUT}
              className="inline-flex items-center gap-2 px-4 py-2 bg-red-600 text-white font-medium rounded-lg hover:bg-red-700 transition text-sm"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
              Logout
            </a>
          </div>
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
                <Image
                  src={session.picture}
                  alt={session.name}
                  width={64}
                  height={64}
                  className="rounded-full object-cover border-2 border-zinc-200 dark:border-zinc-700"
                  unoptimized
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
      </main>
    </div>
  );
}
