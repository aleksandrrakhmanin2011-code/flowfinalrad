// FlowRad Vercel Middleware
// Protects the static site. Login and API routes are handled separately.

export const config = {
  matcher: [
    '/((?!login\\.html|api/|favicon\\.ico|robots\\.txt|_vercel).*)',
  ],
};

const COOKIE_NAME = 'fr_session';
const SESSION_TTL_MS = 1000 * 60 * 60 * 2; // 2 hours

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

async function verifySession(token, secret) {
  if (!token) return false;
  const p = token.split('.');
  if (p.length !== 3) return false;

  const [id, expText, sig] = p;
  const exp = Number(expText);
  if (!id || !Number.isFinite(exp) || Date.now() > exp) return false;

  const expected = await hmac(secret, `${id}.${expText}`);
  return safeEqual(sig, expected);
}

function cookie(req) {
  const raw = req.headers.get('cookie') || '';
  const m = raw.match(/(?:^|;\s*)fr_session=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}

export default async function middleware(req) {
  const secret = process.env.AUTH_SECRET;
  if (!secret) {
    return new Response('AUTH_SECRET is not configured.', { status: 500 });
  }

  if (await verifySession(cookie(req), secret)) return;

  const url = new URL(req.url);
  const login = new URL('/login.html', url);
  login.searchParams.set('next', url.pathname + url.search);

  return Response.redirect(login, 303);
}
