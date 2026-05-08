import { redirect } from 'next/navigation';
import { ROUTES } from '@/lib/oidc/constants';
import { verifyOtp } from '@/lib/oidc/otp';
import { createSessionData } from '@/lib/oidc/session';
import { setSessionCookie } from '@/lib/oidc/cookies';

export async function POST(request: Request) {
  try {
    const form = await request.formData();
    const email = (form.get('email') as string | null)?.trim().toLowerCase() ?? '';
    const otp = (form.get('otp') as string | null)?.trim() ?? '';
    const redirectUri = (form.get('redirect_uri') as string | null) ?? '/';

    if (!email || !otp) {
      return redirect(
        `${ROUTES.OTP_VERIFY_PAGE}?email=${encodeURIComponent(email)}&redirect_uri=${encodeURIComponent(redirectUri)}&error=invalid`
      );
    }

    const result = await verifyOtp(email, otp);

    if (result === 'expired') {
      return redirect(`${ROUTES.ERROR}?code=otp_expired&description=${encodeURIComponent('Your sign-in code has expired. Please request a new one.')}`);
    }

    if (result === 'locked') {
      return redirect(`${ROUTES.ERROR}?code=otp_locked&description=${encodeURIComponent('Too many incorrect attempts. Please request a new sign-in code.')}`);
    }

    if (result === 'invalid') {
      return redirect(
        `${ROUTES.OTP_VERIFY_PAGE}?email=${encodeURIComponent(email)}&redirect_uri=${encodeURIComponent(redirectUri)}&error=invalid`
      );
    }

    // OTP valid — create session using the same infrastructure as OIDC
    const now = Date.now();
    const thirtyDays = 30 * 24 * 60 * 60 * 1000;

    const sessionData = await createSessionData(
      {
        access_token: crypto.randomUUID(),
        id_token: '',
        token_type: 'Bearer',
        expires_in: 30 * 24 * 60 * 60,
        expires_at: now + thirtyDays,
      },
      {
        sub: email,
        name: email.split('@')[0],
        email,
      },
      'email-otp'
    );

    await setSessionCookie(sessionData);
    return redirect(redirectUri);
  } catch (error) {
    if (
      error &&
      typeof error === 'object' &&
      'digest' in error &&
      typeof (error as { digest: unknown }).digest === 'string' &&
      (error as { digest: string }).digest.startsWith('NEXT_REDIRECT')
    ) {
      throw error;
    }

    console.error('[OTP] Verify error:', error);
    return redirect(`${ROUTES.ERROR}?code=otp_error&description=${encodeURIComponent('An error occurred during sign-in. Please try again.')}`);
  }
}
