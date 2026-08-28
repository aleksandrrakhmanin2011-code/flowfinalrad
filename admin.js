import crypto from 'crypto';
import { sql } from '@vercel/postgres';

const ALLOWED_ORIGIN = '*';

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
      'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Key',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    },
  });
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return crypto.timingSafeEqual(aa, bb);
}

function requireAdmin(req) {
  const supplied = req.headers.get('x-admin-key') || '';
  const expected = process.env.ADMIN_KEY || '';
  return !!expected && !!supplied && safeEqual(supplied, expected);
}

function randomKey() {
  return `FR-${crypto.randomBytes(18).toString('base64url')}`;
}

function hashKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

export default async function handler(req) {
  if (req.method === 'OPTIONS') return json({ ok: true });

  if (!requireAdmin(req)) {
    return json({ ok: false, error: 'Unauthorized' }, 401);
  }

  try {
    if (req.method === 'GET') {
      const result = await sql`
        SELECT id, label, created_at, expires_at, revoked, max_sessions,
               device_bound_at, first_ip, last_ip, last_used_at, use_count
        FROM access_keys
        ORDER BY created_at DESC
      `;
      return json({ ok: true, keys: result.rows });
    }

    if (req.method === 'POST') {
      let body;
      try { body = await req.json(); }
      catch { return json({ ok: false, error: 'Invalid JSON' }, 400); }

      const label = String(body?.label || 'Flowrad user').trim().slice(0, 120) || 'Flowrad user';
      const days = Math.max(0, Math.min(3650, Number(body?.days || 0)));
      const maxSessions = [1, 2, 5, 20].includes(Number(body?.maxSessions))
        ? Number(body.maxSessions) : 1;

      const key = randomKey();
      const keyHash = hashKey(key);
      const id = crypto.randomUUID();
      const expires = days > 0 ? new Date(Date.now() + days * 86400000).toISOString() : null;

      await sql`
        INSERT INTO access_keys
          (id, access_key, key_hash, label, expires_at, max_sessions)
        VALUES
          (${id}, ${key}, ${keyHash}, ${label}, ${expires}, ${maxSessions})
      `;

      return json({ ok: true, key, id });
    }

    if (req.method === 'DELETE') {
      const url = new URL(req.url);
      const id = url.searchParams.get('id');
      if (!id) return json({ ok: false, error: 'Missing id' }, 400);

      await sql`
        UPDATE access_keys
        SET revoked = TRUE
        WHERE id = ${id}
      `;

      return json({ ok: true });
    }

    return json({ ok: false, error: 'Method not allowed' }, 405);
  } catch (e) {
    console.error(e);
    return json({ ok: false, error: 'Database/server error' }, 500);
  }
}
