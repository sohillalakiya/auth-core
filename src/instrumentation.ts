/**
 * Next.js instrumentation hook — runs once when the server starts.
 * Warms up Redis and validates config early so the first request is fast.
 *
 * @see https://nextjs.org/docs/app/building-your-application/optimizing/instrumentation
 */

export async function register() {
  if (process.env.NEXT_RUNTIME !== 'nodejs') return;

  const { getConfig } = await import('./lib/oidc/env');
  const { getSessionRegistrySafe } = await import('./lib/oidc/session-registry');

  try {
    getConfig();
  } catch (error) {
    console.error('[auth-core] Configuration error:', error instanceof Error ? error.message : error);
    return;
  }

  // Trigger Redis connection on startup so the first request doesn't pay
  // the connection latency. Connection events are logged by the registry itself.
  getSessionRegistrySafe();
}
