// /api/admin.js
// Local Admin.html talks to this endpoint.
// Admin authentication uses ADMIN_KEY from Vercel Environment Variables.

import { sql } from '@vercel/postgres';
import crypto from 'node:crypto';

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function randomKey() {
  const raw = crypto.randomBytes(18).toString('base64url').toUpperCase();
  return `FR-${raw.slice(0, 6)}-${raw.slice(6, 12)}-${raw.slice(12, 18)}`;
}

function adminOk(req) {
  const configured = process.env.ADMIN_KEY || '';
  const supplied = String(req.headers['x-admin-key'] || '');
  if (!configured || !supplied) return false;
  const a = Buffer.from(configured);
  const b = Buffer.from(supplied);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Key');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Cache-Control', 'no-store');
}

function getIp(req) {
  const xff = req.headers['x-forwarded-for'];
  return (xff ? String(xff).split(',')[0] : req.socket?.remoteAddress) || '';
}

export default async function handler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();

  if (!adminOk(req)) {
    return res.status(401).json({ ok: false, error: 'ADMIN_UNAUTHORIZED' });
  }

  try {
    if (req.method === 'GET') {
      const result = await sql`
        SELECT id, label, created_at, expires_at, revoked,
               max_sessions, first_ip, last_ip, last_used_at, use_count
        FROM access_keys
        ORDER BY created_at DESC
      `;
      return res.status(200).json({ ok: true, keys: result.rows });
    }

    if (req.method === 'POST') {
      const body = req.body || {};
      const label = String(body.label || 'Flowrad user').trim().slice(0, 100);
      const days = Number(body.days);
      const maxSessions = Math.max(1, Math.min(20, Number(body.maxSessions) || 1));

      let expiresAt = null;
      if (Number.isFinite(days) && days > 0) {
        expiresAt = new Date(Date.now() + days * 86400000);
      }

      const plainKey = randomKey();
      const keyHash = sha256(plainKey);
      const id = crypto.randomUUID();

      await sql`
        INSERT INTO access_keys
          (id, access_key, key_hash, label, created_at, expires_at, revoked, max_sessions)
        VALUES
          (${id}, ${keyHash.slice(0, 32)}, ${keyHash}, ${label},
           NOW(), ${expiresAt}, false, ${maxSessions})
      `;

      return res.status(201).json({
        ok: true,
        key: plainKey,
        id,
        label,
        expiresAt
      });
    }

    if (req.method === 'DELETE') {
      const id = String(req.query.id || '');
      if (!id) return res.status(400).json({ ok: false, error: 'MISSING_ID' });

      const result = await sql`
        UPDATE access_keys
        SET revoked = true
        WHERE id = ${id}
        RETURNING id
      `;

      return res.status(result.rowCount ? 200 : 404).json({
        ok: !!result.rowCount,
        error: result.rowCount ? undefined : 'NOT_FOUND'
      });
    }

    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: 'DATABASE_ERROR' });
  }
}
