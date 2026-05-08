import { getSession } from '@/lib/oidc/session';
import { redirect } from 'next/navigation';
import { ROUTES } from '@/lib/oidc/constants';

export default async function LoginPage() {
  const session = await getSession();

  if (session) {
    redirect('/');
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-zinc-50 to-zinc-100 dark:from-black dark:to-zinc-900 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="bg-white dark:bg-zinc-800 rounded-2xl shadow-xl border border-zinc-200 dark:border-zinc-700 overflow-hidden">
          <div className="h-1.5 bg-gradient-to-r from-blue-500 to-purple-600" />

          <div className="p-8">
            <div className="flex justify-center mb-6">
              <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center shadow-lg">
                <svg className="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
            </div>

            <h1 className="text-2xl font-bold text-center text-zinc-900 dark:text-zinc-50 mb-2">
              Sign in
            </h1>
            <p className="text-sm text-center text-zinc-500 dark:text-zinc-400 mb-8">
              Use your organisation account to continue
            </p>

            <div className="space-y-3">
              {/* SSO */}
              <a
                href={`${ROUTES.LOGIN}?redirect_uri=/`}
                className="flex items-center justify-center gap-3 w-full px-4 py-3 bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-medium rounded-xl transition-colors shadow-sm text-sm"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                </svg>
                Sign in with SSO
              </a>

              {/* Divider */}
              <div className="flex items-center gap-3 py-1">
                <div className="flex-1 h-px bg-zinc-200 dark:bg-zinc-700" />
                <span className="text-xs text-zinc-400 dark:text-zinc-500">or</span>
                <div className="flex-1 h-px bg-zinc-200 dark:bg-zinc-700" />
              </div>

              {/* Email OTP */}
              <a
                href={`${ROUTES.OTP_LOGIN}?redirect_uri=/`}
                className="flex items-center justify-center gap-3 w-full px-4 py-3 bg-white dark:bg-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-600 text-zinc-700 dark:text-zinc-200 font-medium rounded-xl border border-zinc-200 dark:border-zinc-600 transition-colors text-sm"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
                Sign in with Email
              </a>
            </div>
          </div>

          <div className="px-8 pb-6 text-center">
            <p className="text-xs text-zinc-400 dark:text-zinc-500">
              Secured with OpenID Connect
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
