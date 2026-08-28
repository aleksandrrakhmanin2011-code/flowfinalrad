import crypto from 'crypto';
import { sql } from '@vercel/postgres';

const COOKIE_NAME = 'fr_session';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Key',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      ...extra,
    },
  });
}

function randomId(bytes = 16) {
  return crypto.randomBytes(bytes).toString('hex');
}

function hashKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

function deviceHash(req) {
  const ua = req.headers.get('user-agent') || '';
  const lang = req.headers.get('accept-language') || '';
  return crypto.createHash('sha256').update(`${ua}|${lang}`).digest('hex');
}

function getClientIp(req) {
  const xf = req.headers.get('x-forwarded-for');
  if (xf) return xf.split(',')[0].trim();
  return req.headers.get('x-real-ip') || '';
}

function setCookie(value) {
  return `${COOKIE_NAME}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}`;
}

export default async function handler(req) {
  if (req.method === 'OPTIONS') return json({ ok: true });
  if (req.method !== 'POST') return json({ ok: false, error: 'Method not allowed' }, 405);

  let body;
  try { body = await req.json(); }
  catch { return json({ ok: false, error: 'Invalid JSON' }, 400); }

  const key = String(body?.password || '').trim();
  if (!key || key.length < 4 || key.length > 200) {
    return json({ ok: false, error: 'Неверный пароль' }, 401);
  }

  const keyHash = hashKey(key);
  const result = await sql`
    SELECT id, access_key, expires_at, revoked, max_sessions, device_hash
    FROM access_keys
    WHERE key_hash = ${keyHash}
    LIMIT 1
  `;
  const row = result.rows[0];

  if (!row || row.revoked || (row.expires_at && new Date(row.expires_at).getTime() <= Date.now())) {
    return json({ ok: false, error: 'Неверный или недействительный пароль' }, 401);
  }

  const ip = getClientIp(req);
  const ua = req.headers.get('user-agent') || '';
  const dev = deviceHash(req);

  // One-device binding: first successful device becomes the bound device.
  if (row.device_hash && row.device_hash !== dev) {
    return json({ ok: false, error: 'Этот пароль уже привязан к другому устройству' }, 403);
  }

  await sql`
    UPDATE access_keys
    SET
      device_hash = COALESCE(device_hash, ${dev}),
      device_bound_at = COALESCE(device_bound_at, NOW()),
      first_ip = COALESCE(first_ip, ${ip}),
      last_ip = ${ip},
      first_user_agent = COALESCE(first_user_agent, ${ua}),
      last_user_agent = ${ua},
      last_used_at = NOW(),
      use_count = use_count + 1
    WHERE id = ${row.id}
  `;

  // Session id includes the access-key id. Middleware validates the signature.
  // A future API can additionally revoke sessions by key id if desired.
  const sessionId = `${row.id}.${randomId(18)}`;
  const secret = process.env.AUTH_SECRET;
  if (!secret) return json({ ok: false, error: 'AUTH_SECRET is not configured' }, 500);

  const hmacKey = await crypto.webcrypto.subtle.importKey(
    'raw',
    Buffer.from(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = Buffer.from(await crypto.webcrypto.subtle.sign(
    'HMAC', hmacKey, Buffer.from(sessionId)
  )).toString('hex');

  return json(
    { ok: true },
    200,
    {
      'Set-Cookie': setCookie(`${sessionId}.${sig}`),
      'Access-Control-Allow-Origin': '*',
    }
  );
}
