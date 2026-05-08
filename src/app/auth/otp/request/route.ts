import { redirect } from 'next/navigation';
import { VALIDATION_PATTERNS, ROUTES } from '@/lib/oidc/constants';
import { generateOtp, storeOtp } from '@/lib/oidc/otp';
import { sendOtpEmail } from '@/lib/email/mailer';

export async function POST(request: Request) {
  try {
    const form = await request.formData();
    const email = (form.get('email') as string | null)?.trim().toLowerCase() ?? '';
    const redirectUri = (form.get('redirect_uri') as string | null) ?? '/';

    if (!email || !VALIDATION_PATTERNS.EMAIL.test(email)) {
      return redirect(
        `${ROUTES.OTP_LOGIN}?error=invalid_email&redirect_uri=${encodeURIComponent(redirectUri)}`
      );
    }

    const otp = generateOtp();
    await storeOtp(email, otp);
    await sendOtpEmail(email, otp);

    return redirect(
      `${ROUTES.OTP_VERIFY_PAGE}?email=${encodeURIComponent(email)}&redirect_uri=${encodeURIComponent(redirectUri)}`
    );
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

    console.error('[OTP] Failed to send OTP:', error);
    return redirect(`${ROUTES.ERROR}?code=otp_send_failed&description=${encodeURIComponent('Failed to send sign-in code. Please try again.')}`);
  }
}
