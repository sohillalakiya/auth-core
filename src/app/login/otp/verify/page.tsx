import { redirect } from 'next/navigation';
import { getSession } from '@/lib/oidc/session';
import { ROUTES } from '@/lib/oidc/constants';

interface Props {
  searchParams: Promise<{ email?: string; error?: string; redirect_uri?: string }>;
}

function maskEmail(email: string): string {
  const [local, domain] = email.split('@');
  if (!domain || !local) return email;
  return `${local[0]}****@${domain}`;
}

export default async function OtpVerifyPage({ searchParams }: Props) {
  const session = await getSession();
  if (session) redirect('/');

  const { email = '', error, redirect_uri = '/' } = await searchParams;

  if (!email) redirect(ROUTES.OTP_LOGIN);

  const errorMessage =
    error === 'invalid' ? 'Incorrect code. Please try again.' : null;

  return (
    <div className="min-h-screen bg-gradient-to-br from-zinc-50 to-zinc-100 dark:from-black dark:to-zinc-900 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="bg-white dark:bg-zinc-800 rounded-2xl shadow-xl border border-zinc-200 dark:border-zinc-700 overflow-hidden">
          <div className="h-1.5 bg-gradient-to-r from-blue-500 to-purple-600" />

          <div className="p-8">
            <div className="flex justify-center mb-6">
              <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center shadow-lg">
                <svg className="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
            </div>

            <h1 className="text-2xl font-bold text-center text-zinc-900 dark:text-zinc-50 mb-2">
              Check your email
            </h1>
            <p className="text-sm text-center text-zinc-500 dark:text-zinc-400 mb-1">
              We sent a 6-digit code to
            </p>
            <p className="text-sm font-medium text-center text-zinc-700 dark:text-zinc-300 mb-8">
              {maskEmail(email)}
            </p>

            {errorMessage && (
              <div className="mb-4 px-4 py-3 rounded-xl bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-sm text-red-700 dark:text-red-300">
                {errorMessage}
              </div>
            )}

            <form action={ROUTES.OTP_VERIFY} method="POST" className="space-y-4">
              <input type="hidden" name="email" value={email} />
              <input type="hidden" name="redirect_uri" value={redirect_uri} />

              <div>
                <label htmlFor="otp" className="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1.5">
                  Sign-in code
                </label>
                <input
                  id="otp"
                  name="otp"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  required
                  maxLength={6}
                  placeholder="123456"
                  autoFocus
                  className="w-full px-4 py-2.5 rounded-xl border border-zinc-200 dark:border-zinc-600 bg-white dark:bg-zinc-700 text-zinc-900 dark:text-zinc-50 placeholder-zinc-400 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm tracking-widest text-center font-mono"
                />
              </div>

              <button
                type="submit"
                className="w-full px-4 py-3 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-medium rounded-xl transition-colors shadow-sm text-sm"
              >
                Verify code
              </button>
            </form>
          </div>

          <div className="px-8 pb-6 text-center space-y-2">
            <p className="text-sm text-zinc-500 dark:text-zinc-400">
              Didn&apos;t receive a code?{' '}
              <a
                href={`${ROUTES.OTP_LOGIN}?email=${encodeURIComponent(email)}&redirect_uri=${encodeURIComponent(redirect_uri)}`}
                className="text-blue-600 dark:text-blue-400 hover:underline font-medium"
              >
                Resend
              </a>
            </p>
            <p>
              <a
                href="/login"
                className="text-sm text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 transition-colors"
              >
                ← Back to sign-in
              </a>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
