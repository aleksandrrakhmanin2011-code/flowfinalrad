// /api/auth.js
// Handles login and creates the signed session cookie.
// Requires a Postgres database connected to Vercel.

import { sql } from '@vercel/postgres';
import crypto from 'node:crypto';

const COOKIE_NAME = 'fr_session';
const SESSION_TTL_MS = 1000 * 60 * 60 * 2;

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function randomId() {
  return crypto.randomBytes(16).toString('hex');
}

function safeEqualHex(a, b) {
  try {
    const aa = Buffer.from(a, 'hex');
    const bb = Buffer.from(b, 'hex');
    return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
  } catch {
    return false;
  }
}

function getIp(req) {
  const xff = req.headers['x-forwarded-for'];
  return (xff ? String(xff).split(',')[0] : req.socket?.remoteAddress) || '';
}

function setCookie(res, value, maxAge) {
  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`
  );
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  try {
    const { password } = typeof req.body === 'object' ? req.body : {};
    const entered = String(password || '');

    if (!entered || entered.length > 300) {
      return res.status(401).json({ ok: false, error: 'INVALID_PASSWORD' });
    }

    const keyHash = sha256(entered);
    const result = await sql`
      SELECT id, expires_at
      FROM access_keys
      WHERE key_hash = ${keyHash}
        AND revoked = false
        AND (expires_at IS NULL OR expires_at > NOW())
      LIMIT 1
    `;

    if (result.rowCount !== 1) {
      return res.status(401).json({ ok: false, error: 'INVALID_PASSWORD' });
    }

    const row = result.rows[0];
    const sessionId = randomId();
    const exp = Date.now() + SESSION_TTL_MS;
    const secret = process.env.AUTH_SECRET;
    const data = `${row.id}.${exp}`;

    const h = crypto.createHmac('sha256', secret).update(data).digest('hex');
    const token = `${row.id}.${exp}.${h}`;

    await sql`
      UPDATE access_keys
      SET last_ip = ${getIp(req)},
          last_user_agent = ${String(req.headers['user-agent'] || '').slice(0, 500)},
          last_used_at = NOW(),
          use_count = use_count + 1
      WHERE id = ${row.id}
    `;

    setCookie(res, token, SESSION_TTL_MS / 1000);
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: 'DATABASE_ERROR' });
  }
}
