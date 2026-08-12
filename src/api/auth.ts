import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import { db, User, SessionRow } from './db';

const COOKIE = 'kc_session';
const SESSION_DAYS = 7;

export const SESSION_COOKIE = COOKIE;

export async function createSession(res: Response, userId: string): Promise<void> {
  const token = await bcrypt.genSalt(32).then((s) => s.replace(/\//g, 'x'));
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 86400_000).toISOString();
  const { error } = await db.from('sessions').insert({ token, user_id: userId, expires_at: expiresAt });
  if (error) throw error;
  res.cookie(COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: SESSION_DAYS * 86400_000,
    path: '/',
  });
}

export async function destroySession(req: Request, res: Response): Promise<void> {
  const token = req.cookies?.[COOKIE];
  if (token) {
    await db.from('sessions').delete().eq('token', token);
  }
  res.clearCookie(COOKIE, { path: '/' });
}

export async function currentUser(req: Request): Promise<User | null> {
  const token = req.cookies?.[COOKIE];
  if (!token) return null;
  const { data } = await db
    .from('sessions')
    .select('*, user:users(*)')
    .eq('token', token)
    .maybeSingle() as { data: (SessionRow & { user: User }) | null };
  if (!data) return null;
  if (new Date(data.expires_at).getTime() < Date.now()) {
    await db.from('sessions').delete().eq('token', token);
    return null;
  }
  return data.user ?? null;
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  (async () => {
    const user = await currentUser(req);
    if (!user) {
      res.status(401).json({ error: 'unauthorized' });
      return;
    }
    (req as any).user = user;
    next();
  })().catch((e) => {
    console.error('requireAuth error', e);
    res.status(500).json({ error: 'server_error' });
  });
}

export function requireRole(...roles: Array<'farmer' | 'wholesaler' | 'admin'>) {
  return (req: Request, res: Response, next: NextFunction) => {
    (async () => {
      const user = await currentUser(req);
      if (!user) {
        res.status(401).json({ error: 'unauthorized' });
        return;
      }
      if (!roles.includes(user.role)) {
        res.status(403).json({ error: 'forbidden' });
        return;
      }
      (req as any).user = user;
      next();
    })().catch((e) => {
      console.error('requireRole error', e);
      res.status(500).json({ error: 'server_error' });
    });
  };
}

export async function verifyPin(user: User, pin: string): Promise<boolean> {
  try {
    return await bcrypt.compare(pin, user.pin_hash);
  } catch {
    return false;
  }
}

export async function hashPin(pin: string): Promise<string> {
  return bcrypt.hash(pin, 10);
}
