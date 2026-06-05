// =============================================================================
// TicketEx Proxy Server
// Deploy on Render (Free tier or above).
//
// Required environment variables (set in Render dashboard → Environment):
//   CSV_SOURCE_URL  — the third-party CSV URL that is CORS-blocked in browsers
//   FRONTEND_URL    — your Vercel URL(s), comma-separated
//                     e.g. https://ticketex.vercel.app,http://127.0.0.1:5500
//
// Render automatically injects PORT — do not set it manually.
// =============================================================================

'use strict';

const express   = require('express');
const cors      = require('cors');
const fetch     = require('node-fetch'); // node-fetch v2 — CommonJS compatible

const app  = express();
const PORT = process.env.PORT || 3000;

// ── 1. CORS ───────────────────────────────────────────────────────────────────
// Build the allowed-origin list from FRONTEND_URL (comma-separated) plus a
// hardcoded set of local-dev origins that are always permitted.

const PROD_ORIGINS = (process.env.FRONTEND_URL || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

const DEV_ORIGINS = [
  'http://127.0.0.1:5500',
  'http://localhost:5500',
  'http://127.0.0.1:5501',
  'http://localhost:5501',
  'http://127.0.0.1:3000',
  'http://localhost:3000',
];

const ALLOWED_ORIGINS = [...new Set([...PROD_ORIGINS, ...DEV_ORIGINS])];

app.use(cors({
  origin(incomingOrigin, callback) {
    // Requests with no Origin header (curl, Postman, server-to-server) are OK
    if (!incomingOrigin) return callback(null, true);

    if (ALLOWED_ORIGINS.includes(incomingOrigin)) {
      return callback(null, true);
    }

    console.warn(`[cors] rejected origin: ${incomingOrigin}`);
    callback(new Error(`CORS policy: origin "${incomingOrigin}" is not allowed.`));
  },
  methods:              ['GET', 'OPTIONS'],
  allowedHeaders:       ['Content-Type'],
  optionsSuccessStatus: 200,
}));

// ── 2. SECURITY HEADERS ───────────────────────────────────────────────────────
// Minimal hardening for a public-facing proxy endpoint.
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options',        'DENY');
  next();
});

// ── 3. HEALTH CHECK ───────────────────────────────────────────────────────────
// Render's zero-downtime deploys ping this before routing traffic.
// Also useful for uptime monitors (UptimeRobot, BetterUptime, etc.).
app.get('/health', (_req, res) => {
  res.json({
    status:    'ok',
    timestamp: new Date().toISOString(),
    uptime:    Math.floor(process.uptime()),
  });
});

// ── 4. PROXY ENDPOINT ─────────────────────────────────────────────────────────
// GET /api/bookings
//
// Fetches the CSV from CSV_SOURCE_URL and returns it to the frontend.
// Headers set on the response:
//   Content-Type       — text/csv so the browser handles it correctly
//   Cache-Control      — no-store so every Refresh click fetches fresh data
//   X-Rows-Fetched     — byte size logged for observability

const FETCH_TIMEOUT_MS = 15_000; // 15 seconds — plenty for any CSV

app.get('/api/bookings', async (_req, res) => {
  const csvUrl = process.env.CSV_SOURCE_URL;

  // Guard: env var must be set before the server is useful
  if (!csvUrl) {
    console.error('[proxy] CSV_SOURCE_URL is not set');
    return res.status(500).json({
      error: 'Server misconfiguration: CSV_SOURCE_URL environment variable is missing.',
    });
  }

  // Abort controller gives us a clean timeout on the upstream fetch
  const controller = new AbortController();
  const timer      = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const upstream = await fetch(csvUrl, {
      signal:  controller.signal,
      headers: {
        // Some origin servers reject requests without a User-Agent
        'User-Agent': 'TicketEx-Proxy/1.0 (+https://github.com/your-repo)',
        'Accept':     'text/csv, text/plain, */*',
      },
    });

    clearTimeout(timer);

    if (!upstream.ok) {
      console.error(`[proxy] upstream ${upstream.status} for ${csvUrl}`);
      return res.status(upstream.status).json({
        error: `Upstream data source returned HTTP ${upstream.status} (${upstream.statusText}).`,
      });
    }

    const csvText = await upstream.text();

    // Tell the browser / CDN never to cache this — each refresh must be live
    res.setHeader('Content-Type',       'text/csv; charset=utf-8');
    res.setHeader('Cache-Control',      'no-store, no-cache, must-revalidate');
    res.setHeader('X-Rows-Fetched',     csvText.split('\n').length - 1); // approx row count

    console.log(`[proxy] served ${csvText.length} bytes from upstream`);
    res.send(csvText);

  } catch (err) {
    clearTimeout(timer);

    if (err.name === 'AbortError') {
      console.error(`[proxy] upstream timed out after ${FETCH_TIMEOUT_MS}ms`);
      return res.status(504).json({ error: 'Upstream data source timed out.' });
    }

    console.error('[proxy] fetch error:', err.message);
    res.status(502).json({ error: 'Failed to reach the upstream data source.' });
  }
});

// ── 5. 404 CATCH-ALL ──────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

// ── 6. GLOBAL ERROR HANDLER ───────────────────────────────────────────────────
// Catches CORS errors and any other Express errors
app.use((err, _req, res, _next) => {
  console.error('[error]', err.message);
  res.status(403).json({ error: err.message });
});

// ── 7. START + GRACEFUL SHUTDOWN ─────────────────────────────────────────────
// Render sends SIGTERM before replacing the old instance — drain in-flight
// requests cleanly instead of dropping them.
const server = app.listen(PORT, () => {
  console.log(`[startup] TicketEx proxy running on port ${PORT}`);
  console.log(`[startup] Allowed origins: ${ALLOWED_ORIGINS.join(', ')}`);
  console.log(`[startup] CSV source configured: ${!!process.env.CSV_SOURCE_URL}`);
});

function shutdown(signal) {
  console.log(`[shutdown] Received ${signal} — closing server`);
  server.close(() => {
    console.log('[shutdown] All connections closed. Exiting.');
    process.exit(0);
  });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
