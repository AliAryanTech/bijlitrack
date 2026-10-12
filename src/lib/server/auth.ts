import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';

export interface AuthUser {
  id: string;
  tokenVersion?: number;
}

export const AUTH_COOKIE_NAME = 'token';

export function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT_SECRET is not defined in environment variables');
  }
  return secret;
}

export function signToken(
  payload: { id: string; tokenVersion?: number },
  expiresIn: string = '24h'
): string {
  return jwt.sign(payload, getJwtSecret(), {
    algorithm: 'HS256',
    expiresIn: expiresIn as any,
  });
}

export function setAuthCookie(response: NextResponse, token: string) {
  response.cookies.set({
    name: AUTH_COOKIE_NAME,
    value: token,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60 * 24, // 24 hours in seconds
  });
}

export function clearAuthCookie(response: NextResponse) {
  response.cookies.set({
    name: AUTH_COOKIE_NAME,
    value: '',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  });
}

export function verifyAuth(req: NextRequest): AuthUser {
  // 1. Check HTTP-only cookie first
  let token = req.cookies.get(AUTH_COOKIE_NAME)?.value;

  // 2. Fallback to Authorization Bearer header
  if (!token) {
    const authHeader = req.headers.get('authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    }
  }

  if (!token) {
    throw new Error('Not authorized, no token provided');
  }

  try {
    const decoded = jwt.verify(token, getJwtSecret(), {
      algorithms: ['HS256'],
    }) as { id: string; tokenVersion?: number };

    return { id: decoded.id, tokenVersion: decoded.tokenVersion };
  } catch (err: any) {
    throw new Error('Not authorized, token invalid or expired');
  }
}

