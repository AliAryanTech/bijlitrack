import { NextRequest, NextResponse } from 'next/server';
import { connectDB } from '@/lib/server/db';
import { User } from '@/lib/server/models';
import { signToken, setAuthCookie } from '@/lib/server/auth';
import { checkRateLimit, getClientIp } from '@/lib/server/rateLimit';

export async function POST(req: NextRequest) {
  try {
    const ip = getClientIp(req);
    const rateCheck = checkRateLimit(`signup:${ip}`, 5, 60_000);
    if (!rateCheck.success) {
      return NextResponse.json(
        { message: 'Too many signup attempts. Please wait a minute and try again.' },
        { status: 429 }
      );
    }

    await connectDB();
    const body = await req.json();
    const { name, email, password } = body;

    const normalizedEmail = email?.toLowerCase().trim();
    if (!normalizedEmail || !password || !name) {
      return NextResponse.json(
        { message: 'Name, email, and password are required' },
        { status: 400 }
      );
    }

    if (typeof password !== 'string' || password.length < 8) {
      return NextResponse.json(
        { message: 'Password must be at least 8 characters long' },
        { status: 400 }
      );
    }

    if (password.length > 128) {
      return NextResponse.json(
        { message: 'Password exceeds maximum length limit' },
        { status: 400 }
      );
    }

    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return NextResponse.json(
        { message: 'Unable to register this email. If you already have an account, please log in.' },
        { status: 400 }
      );
    }

    const user = new User({
      name: name.trim().slice(0, 100),
      email: normalizedEmail,
      passwordHash: password, // Mongoose pre-save hook hashes this with bcryptjs
      tokenVersion: 0,
    });

    await user.save();

    const token = signToken({
      id: user._id.toString(),
      tokenVersion: user.tokenVersion || 0,
    });

    const response = NextResponse.json(
      {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      },
      { status: 201 }
    );

    setAuthCookie(response, token);

    return response;
  } catch (error: any) {
    console.error('[Auth Signup Error]', error);
    return NextResponse.json(
      { message: 'Error creating user. Please try again.' },
      { status: 500 }
    );
  }
}
