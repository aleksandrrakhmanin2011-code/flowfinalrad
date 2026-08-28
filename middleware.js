// FlowRad Vercel Routing Middleware
// Protects the static site with a signed session cookie.
// IMPORTANT: /api/* is public to the middleware so auth/admin API routes can run.

export const config = {
  matcher: [
    // Run on everything except:
    // - /login.html
    // - /api/*
    // - Vercel internals / common static files
    '/((?!login\\.html$|api(?:/|$)|_vercel/|favicon\\.ico$|robots\\.txt$).*)',
  ],
};

const COOKIE_NAME = 'fr_session';

function hex(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const sig = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(data),
  );

  return hex(sig);
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) {
    return false;
  }

  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function getCookie(request, name) {
  const raw = request.headers.get('cookie') || '';
  const match = raw.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  if (!match) return null;

  try {
    return decodeURIComponent(match[1]);
  } catch {
    return null;
  }
}

async function verifySession(secret, token) {
  if (!token) return null;

  const dot = token.lastIndexOf('.');
  if (dot <= 0 || dot === token.length - 1) return null;

  const sessionId = token.slice(0, dot);
  const signature = token.slice(dot + 1);
  const expected = await hmac(secret, sessionId);

  return safeEqual(signature, expected) ? sessionId : null;
}

export default async function middleware(request) {
  const url = new URL(request.url);

  // These are deliberately allowed through this middleware.
  // /api/auth and /api/admin perform their own authentication.
  if (
    url.pathname === '/login.html' ||
    url.pathname === '/favicon.ico' ||
    url.pathname === '/robots.txt' ||
    url.pathname === '/api' ||
    url.pathname.startsWith('/api/') ||
    url.pathname.startsWith('/_vercel/')
  ) {
    return undefined;
  }

  const secret = process.env.AUTH_SECRET;
  if (!secret) {
    return new Response('AUTH_SECRET is not configured.', {
      status: 500,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    });
  }

  const token = getCookie(request, COOKIE_NAME);
  const sessionId = await verifySession(secret, token);

  if (!sessionId) {
    const login = new URL('/login.html', request.url);
    login.searchParams.set('next', url.pathname + url.search);

    return new Response(null, {
      status: 303,
      headers: {
        Location: login.toString(),
        'Cache-Control': 'no-store',
      },
    });
  }

  // Vercel Routing Middleware continues when no response is returned.
  // The API remains responsible for creating/revoking sessions.
  return undefined;
}
