import nodemailer from 'nodemailer';

interface SmtpConfig {
  host: string;
  port: number;
  user: string;
  pass: string;
  from: string;
}

function getSmtpConfig(): SmtpConfig {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
    throw new Error('SMTP_HOST, SMTP_USER, and SMTP_PASS environment variables are required for email OTP');
  }
  return {
    host: SMTP_HOST,
    port: SMTP_PORT ? parseInt(SMTP_PORT, 10) : 587,
    user: SMTP_USER,
    pass: SMTP_PASS,
    from: SMTP_FROM || SMTP_USER,
  };
}

let _transporter: nodemailer.Transporter | null = null;

function getTransporter(): nodemailer.Transporter {
  if (!_transporter) {
    const cfg = getSmtpConfig();
    _transporter = nodemailer.createTransport({
      host: cfg.host,
      port: cfg.port,
      secure: false, // STARTTLS on port 587
      auth: { user: cfg.user, pass: cfg.pass },
    });
  }
  return _transporter;
}

export async function sendOtpEmail(to: string, otp: string): Promise<void> {
  const cfg = getSmtpConfig();

  const html = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f4f4f5;font-family:system-ui,-apple-system,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 16px;">
    <tr><td align="center">
      <table width="480" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:16px;border:1px solid #e4e4e7;overflow:hidden;">
        <tr><td style="height:4px;background:linear-gradient(90deg,#3b82f6,#9333ea);"></td></tr>
        <tr><td style="padding:40px 40px 32px;">
          <p style="margin:0 0 8px;font-size:13px;color:#71717a;text-transform:uppercase;letter-spacing:0.05em;">Sign-in code</p>
          <p style="margin:0 0 24px;font-size:14px;color:#3f3f46;">Use the code below to complete your sign-in. It expires in <strong>5 minutes</strong>.</p>
          <div style="background:#f4f4f5;border-radius:12px;padding:24px;text-align:center;margin:0 0 24px;">
            <span style="font-size:40px;font-weight:700;letter-spacing:12px;color:#18181b;font-family:monospace;">${otp}</span>
          </div>
          <p style="margin:0;font-size:13px;color:#a1a1aa;">If you didn't request this code, you can safely ignore this email.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;

  await getTransporter().sendMail({
    from: `"Sign-in" <${cfg.from}>`,
    to,
    subject: `${otp} is your sign-in code`,
    text: `Your sign-in code is: ${otp}\n\nThis code expires in 5 minutes.\n\nIf you didn't request this, ignore this email.`,
    html,
  });
}
