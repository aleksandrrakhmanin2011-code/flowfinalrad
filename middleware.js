// FlowRad Vercel Edge Middleware
// Protects the static site before files are sent to the browser.
// Public: /login.html and /api/*
// Protected: everything else, including / and /index.html.

export const config = {
  matcher: [
    '/((?!login\\.html$|api/|favicon\\.ico$|robots\\.txt$|_vercel/).*)',
  ],
};

const COOKIE_NAME = 'fr_session';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days

function hex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(data)
  );
  return hex(sig);
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function getCookie(req, name) {
  const raw = req.headers.get('cookie') || '';
  const m = raw.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return m ? decodeURIComponent(m[1]) : null;
}

// Token contains only an opaque session id + HMAC.
// The database is authoritative for revocation and expiry.
async function makeSession(secret, sessionId) {
  const payload = `${sessionId}`;
  const sig = await hmac(secret, payload);
  return `${sessionId}.${sig}`;
}

async function verifySession(secret, token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [sessionId, sig] = parts;
  if (!sessionId || !safeEqual(sig, await hmac(secret, sessionId))) return null;
  return sessionId;
}

export default async function middleware(req) {
  const url = new URL(req.url);
  const secret = process.env.AUTH_SECRET;

  // Never use SITE_PASSWORD in this version.
  if (!secret) {
    return new Response('AUTH_SECRET is not configured.', { status: 500 });
  }

  const token = getCookie(req, COOKIE_NAME);
  const sessionId = await verifySession(secret, token);

  if (!sessionId) {
    const dest = new URL('/login.html', req.url);
    dest.searchParams.set('next', url.pathname + url.search);
    return new Response(null, {
      status: 303,
      headers: { Location: dest.toString() },
    });
  }

  // The session is cryptographically valid. API is responsible for creating
  // and revoking sessions. Static middleware stays DB-free for performance.
  return undefined;
}

// Export helpers for documentation/testing only.
export { makeSession, verifySession, COOKIE_NAME, SESSION_TTL_SECONDS };
