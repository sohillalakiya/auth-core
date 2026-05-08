import { redirect } from 'next/navigation';
import { getSession } from '@/lib/oidc/session';
import { getConfig } from '@/lib/oidc/env';
import { ROUTES } from '@/lib/oidc/constants';
import TodoList from './TodoList';

export default async function TodosPage() {
  const session = await getSession();

  if (!session) {
    redirect('/login');
  }

  const { dpopEnabled } = getConfig();

  return (
    <div className="min-h-screen bg-gradient-to-br from-zinc-50 to-zinc-100 dark:from-black dark:to-zinc-900">
      <main className="container mx-auto px-4 py-16 max-w-2xl">
        {/* Header */}
        <div className="flex items-center justify-between mb-10">
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-zinc-50">Todo List</h1>
            <p className="text-zinc-500 dark:text-zinc-400 text-sm mt-1">
              Stored locally in your browser
            </p>
          </div>
          <a
            href={ROUTES.HOME}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-50 border border-zinc-200 dark:border-zinc-700 rounded-xl hover:bg-zinc-50 dark:hover:bg-zinc-800 transition-colors"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            Dashboard
          </a>
        </div>

        {/* Card */}
        <div className="bg-white dark:bg-zinc-800 rounded-2xl shadow-lg border border-zinc-200 dark:border-zinc-700 p-6">
          <TodoList accessToken={session.access_token} dpopEnabled={dpopEnabled} />
        </div>
      </main>
    </div>
  );
}
