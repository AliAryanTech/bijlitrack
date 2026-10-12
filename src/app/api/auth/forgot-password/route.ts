import { NextRequest, NextResponse } from 'next/server';
import crypto from 'node:crypto';
import { connectDB } from '@/lib/server/db';
import { User } from '@/lib/server/models';
import { isMailConfigured, sendPasswordResetEmail } from '@/lib/server/services/mail.service';
import { checkRateLimit, getClientIp } from '@/lib/server/rateLimit';

const RESET_TOKEN_EXPIRES_MS = 60 * 60 * 1000;

const hashResetToken = (token: string) => {
  return crypto.createHash('sha256').update(token).digest('hex');
};

const getFrontendUrl = (req: NextRequest) => {
  if (process.env.FRONTEND_URL) {
    return process.env.FRONTEND_URL.replace(/\/$/, '');
  }
  if (process.env.NEXT_PUBLIC_APP_URL) {
    return process.env.NEXT_PUBLIC_APP_URL.replace(/\/$/, '');
  }
  if (process.env.VERCEL_PROJECT_PRODUCTION_URL) {
    return `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL.replace(/\/$/, '')}`;
  }

  // Safe host fallback validation
  const rawHost = req.headers.get('host') || 'localhost:3000';
  const isSafeHost = /^(localhost(:\d+)?|127\.0\.0\.1(:\d+)?|[a-zA-Z0-9-]+\.vercel\.app)$/i.test(rawHost);
  const host = isSafeHost ? rawHost : 'bijlitrack.vercel.app';
  const proto = host.includes('localhost') || host.includes('127.0.0.1') ? 'http' : 'https';
  return `${proto}://${host}`;
};

export async function POST(req: NextRequest) {
  const genericMessage = 'If an account exists for this email, a password reset link has been generated.';

  try {
    const ip = getClientIp(req);
    const rateCheck = checkRateLimit(`forgot-pw:${ip}`, 5, 300_000); // 5 requests per 5 minutes
    if (!rateCheck.success) {
      return NextResponse.json(
        { message: 'Too many password reset attempts. Please wait a few minutes.' },
        { status: 429 }
      );
    }

    await connectDB();
    const { email } = await req.json();

    if (!email) {
      return NextResponse.json({ message: 'Email is required' }, { status: 400 });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail }).select(
      '+passwordResetTokenHash +passwordResetExpiresAt'
    );

    if (!user) {
      return NextResponse.json({ message: genericMessage });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.passwordResetTokenHash = hashResetToken(resetToken);
    user.passwordResetExpiresAt = new Date(Date.now() + RESET_TOKEN_EXPIRES_MS);
    await user.save();

    const baseUrl = getFrontendUrl(req);
    const resetUrl = `${baseUrl}/reset-password?token=${resetToken}`;

    let mailSent = false;
    if (isMailConfigured()) {
      await sendPasswordResetEmail({
        to: user.email,
        name: user.name,
        resetUrl,
      });
      mailSent = true;
    }

    // Never return reset token in response. Log locally for developer convenience if email isn't configured
    if (process.env.NODE_ENV !== 'production' && !mailSent) {
      console.log('[Dev Notice] Password reset link (email service not configured):', resetUrl);
    }

    return NextResponse.json({
      message: genericMessage,
      emailSent: mailSent,
    });
  } catch (error: any) {
    console.error('[Auth Forgot Password Error]', error);
    return NextResponse.json(
      { message: 'Error creating password reset link. Please try again later.' },
      { status: 500 }
    );
  }
}
