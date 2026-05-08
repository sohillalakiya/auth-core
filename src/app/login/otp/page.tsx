import { redirect } from 'next/navigation';
import { getSession } from '@/lib/oidc/session';
import { ROUTES } from '@/lib/oidc/constants';

interface Props {
  searchParams: Promise<{ error?: string; redirect_uri?: string; email?: string }>;
}

export default async function OtpLoginPage({ searchParams }: Props) {
  const session = await getSession();
  if (session) redirect('/');

  const { error, redirect_uri = '/', email = '' } = await searchParams;

  const errorMessage =
    error === 'invalid_email' ? 'Please enter a valid email address.' : null;

  return (
    <div className="min-h-screen bg-gradient-to-br from-zinc-50 to-zinc-100 dark:from-black dark:to-zinc-900 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="bg-white dark:bg-zinc-800 rounded-2xl shadow-xl border border-zinc-200 dark:border-zinc-700 overflow-hidden">
          <div className="h-1.5 bg-gradient-to-r from-blue-500 to-purple-600" />

          <div className="p-8">
            <div className="flex justify-center mb-6">
              <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center shadow-lg">
                <svg className="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
              </div>
            </div>

            <h1 className="text-2xl font-bold text-center text-zinc-900 dark:text-zinc-50 mb-2">
              Sign in with email
            </h1>
            <p className="text-sm text-center text-zinc-500 dark:text-zinc-400 mb-8">
              We&apos;ll send a 6-digit code to your inbox
            </p>

            {errorMessage && (
              <div className="mb-4 px-4 py-3 rounded-xl bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-sm text-red-700 dark:text-red-300">
                {errorMessage}
              </div>
            )}

            <form action={ROUTES.OTP_REQUEST} method="POST" className="space-y-4">
              <input type="hidden" name="redirect_uri" value={redirect_uri} />

              <div>
                <label htmlFor="email" className="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1.5">
                  Email address
                </label>
                <input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  defaultValue={email}
                  placeholder="you@example.com"
                  className="w-full px-4 py-2.5 rounded-xl border border-zinc-200 dark:border-zinc-600 bg-white dark:bg-zinc-700 text-zinc-900 dark:text-zinc-50 placeholder-zinc-400 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                />
              </div>

              <button
                type="submit"
                className="w-full px-4 py-3 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-medium rounded-xl transition-colors shadow-sm text-sm"
              >
                Send code
              </button>
            </form>
          </div>

          <div className="px-8 pb-6 text-center">
            <a
              href="/login"
              className="text-sm text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 transition-colors"
            >
              ← Back to sign-in
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
