import { NextRequest, NextResponse } from 'next/server';
import { connectDB } from '@/lib/server/db';
import { User } from '@/lib/server/models';
import { verifyAuth } from '@/lib/server/auth';

export async function GET(req: NextRequest) {
  try {
    const authUser = verifyAuth(req);
    await connectDB();

    const user = await User.findById(authUser.id).select('-passwordHash');
    if (!user) {
      return NextResponse.json({ message: 'User not found' }, { status: 404 });
    }

    if (
      authUser.tokenVersion !== undefined &&
      user.tokenVersion !== undefined &&
      authUser.tokenVersion !== user.tokenVersion
    ) {
      return NextResponse.json(
        { message: 'Session expired due to password change. Please log in again.' },
        { status: 401 }
      );
    }

    return NextResponse.json(user);
  } catch (error: any) {
    const status = error.message.includes('Not authorized') ? 401 : 500;
    return NextResponse.json(
      { message: error.message || 'Error fetching user' },
      { status }
    );
  }
}
