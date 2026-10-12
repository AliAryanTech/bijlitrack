import { NextRequest, NextResponse } from 'next/server';
import { connectDB } from '@/lib/server/db';
import { User } from '@/lib/server/models';
import { signToken, setAuthCookie } from '@/lib/server/auth';
import { checkRateLimit, getClientIp } from '@/lib/server/rateLimit';

export async function POST(req: NextRequest) {
  try {
    const ip = getClientIp(req);
    const rateCheck = checkRateLimit(`login:${ip}`, 10, 60_000);
    if (!rateCheck.success) {
      return NextResponse.json(
        { message: 'Too many login attempts. Please wait a minute and try again.' },
        { status: 429 }
      );
    }

    await connectDB();
    const body = await req.json();
    const { email, password } = body;

    const normalizedEmail = email?.toLowerCase().trim();
    if (!normalizedEmail || !password) {
      return NextResponse.json(
        { message: 'Email and password are required' },
        { status: 400 }
      );
    }

    const maskedEmail = normalizedEmail.replace(/^(.)(.*)(@.*)$/, (_m: string, a: string, b: string, c: string) => `${a}${'*'.repeat(Math.max(b.length, 1))}${c}`);
    console.log(`[Auth] Login attempt for: ${maskedEmail}`);

    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      console.warn(`[Auth] Login failed - user not found in database: ${maskedEmail}`);
      return NextResponse.json({ message: 'Invalid credentials' }, { status: 401 });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      console.warn(`[Auth] Login failed - incorrect password for: ${maskedEmail}`);
      return NextResponse.json({ message: 'Invalid credentials' }, { status: 401 });
    }

    const token = signToken({
      id: user._id.toString(),
      tokenVersion: user.tokenVersion || 0,
    });

    const response = NextResponse.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });

    setAuthCookie(response, token);

    return response;
  } catch (error: any) {
    console.error('[Auth Login Error]', error);
    return NextResponse.json(
      { message: 'Error during login. Please try again.' },
      { status: 500 }
    );
  }
}
