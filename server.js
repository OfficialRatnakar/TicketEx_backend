// =============================================================================
// TicketEx Proxy + Auth Server
// Deploy on Render (Free tier or above).
//
// Required environment variables (set in Render dashboard → Environment):
//   CSV_SOURCE_URL  — the third-party CSV URL that is CORS-blocked in browsers
//   FRONTEND_URL    — your Vercel URL(s), comma-separated
//   JWT_SECRET      — long random string for signing tokens
//   EMAIL_USER      — Gmail address used to send OTPs
//   EMAIL_PASS      — Gmail App Password (not your account password)
//   MONGODB_URI     — MongoDB Atlas connection string
//
// Render automatically injects PORT — do not set it manually.
// =============================================================================

'use strict';

const express  = require('express');
const cors     = require('cors');
const fetch    = require('node-fetch');
const jwt      = require('jsonwebtoken');
const mongoose = require('mongoose');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── 1. MONGOOSE CONNECTION ────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('[db] Connected to MongoDB'))
  .catch(err => console.error('[db] Connection error:', err.message));

// ── 2. SCHEMA & MODEL ─────────────────────────────────────────────────────────
const loginLogSchema = new mongoose.Schema({
  email:     { type: String, required: true },
  role:      { type: String, required: true },
  timestamp: { type: Date,   default: Date.now },
});

const LoginLog = mongoose.model('LoginLog', loginLogSchema);

// ── 3. USERS ALLOWLIST ────────────────────────────────────────────────────────
// Only emails listed here may request an OTP.
// const USERS = [
//   { email: 'vishalratnakar453@gmail.com', role: 'admin' },
//   // Add more users here: { email: 'worker@company.com', role: 'employee' }
// ];

const USERS = [
  { email: 'vishalratnakar453@gmail.com', role: 'admin' },
  { email: 'vishal.ratnakar@ticketex.co',          role: 'employee' },
  { email: 'yogesh.parashar@ticketex.co',          role: 'employee' },
];

// ── 4. IN-MEMORY OTP STORE ────────────────────────────────────────────────────
// OTPs are single-use and expire after 10 minutes.
// Map<email, { otp: string, expiresAt: number }>



const otpStore = new Map();
const OTP_TTL_MS = 10 * 60 * 1000;

// ── 5. EMAIL SENDER (Resend — HTTPS API, no SMTP ports needed) ───────────────
async function sendOtpEmail(to, otp) {
  const res = await fetch('https://api.resend.com/emails', {
    method:  'POST',
    headers: {
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type':  'application/json',
    },
    body: JSON.stringify({
      from:    'TicketEx Auth <onboarding@resend.dev>',
      to:      [to],
      subject: 'Your TicketEx Login OTP',
      html: `
        <div style="font-family:sans-serif;max-width:400px;margin:0 auto">
          <h2 style="color:#00d4ff">TicketEx Login</h2>
          <p>Your one-time password is:</p>
          <div style="font-size:36px;font-weight:700;letter-spacing:8px;color:#00d4ff;padding:20px 0">${otp}</div>
          <p style="color:#999;font-size:13px">Expires in 10 minutes. Do not share it.</p>
        </div>
      `,
    }),
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.message || `Resend error ${res.status}`);
  }
}

// ── 6. CORS ───────────────────────────────────────────────────────────────────
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
    if (!incomingOrigin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(incomingOrigin)) return callback(null, true);
    console.warn(`[cors] rejected origin: ${incomingOrigin}`);
    callback(new Error(`CORS policy: origin "${incomingOrigin}" is not allowed.`));
  },
  methods:              ['GET', 'POST', 'OPTIONS'],
  allowedHeaders:       ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 200,
}));

// ── 7. SECURITY HEADERS & BODY PARSING ───────────────────────────────────────
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options',        'DENY');
  next();
});

app.use(express.json());

// ── 8. AUTH MIDDLEWARE ────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token      = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) return res.status(401).json({ error: 'Missing token.' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: admin access only.' });
  }
  next();
}

// ── 9. HEALTH CHECK ───────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({
    status:    'ok',
    timestamp: new Date().toISOString(),
    uptime:    Math.floor(process.uptime()),
    db:        mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
  });
});

// ── 10. AUTH — REQUEST OTP ─────────────────────────────────────────────────────
// POST /api/auth/send-otp   body: { email }
// Generates a 6-digit OTP, stores it in memory, and emails it to the user.

app.post('/api/auth/send-otp', async (req, res) => {
  const email = (req.body.email || '').toLowerCase().trim();

  const user = USERS.find(u => u.email.toLowerCase() === email);
  if (!user) {
    // Return the same response for unknown emails to avoid user enumeration
    return res.json({ message: 'If that email is registered, an OTP has been sent.' });
  }

  const otp       = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Date.now() + OTP_TTL_MS;
  otpStore.set(email, { otp, expiresAt });

  try {
    await sendOtpEmail(email, otp);
    console.log(`[otp] Sent OTP to ${email}`);
    res.json({ message: 'If that email is registered, an OTP has been sent.' });

  } catch (err) {
    console.error('[otp] Email send error:', err.message);
    otpStore.delete(email);
    res.status(500).json({ error: 'Failed to send OTP. Please try again.' });
  }
});

// ── 11. AUTH — VERIFY OTP ─────────────────────────────────────────────────────
// POST /api/auth/verify-otp   body: { email, otp }
// Validates the OTP, issues a JWT, and logs the login to MongoDB.

app.post('/api/auth/verify-otp', async (req, res) => {
  const email = (req.body.email || '').toLowerCase().trim();
  const otp   = (req.body.otp   || '').trim();

  const user = USERS.find(u => u.email.toLowerCase() === email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

  const record = otpStore.get(email);
  if (!record)                          return res.status(401).json({ error: 'No OTP found. Please request a new one.' });
  if (Date.now() > record.expiresAt)    { otpStore.delete(email); return res.status(401).json({ error: 'OTP has expired. Please request a new one.' }); }
  if (record.otp !== otp)               return res.status(401).json({ error: 'Incorrect OTP.' });

  otpStore.delete(email); // single-use

  const token = jwt.sign(
    { email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '8h' }
  );

  // Persist login event to MongoDB
  try {
    await LoginLog.create({ email: user.email, role: user.role });
  } catch (dbErr) {
    console.error('[db] Failed to save login log:', dbErr.message);
    // Non-fatal — still issue the token
  }

  console.log(`[auth] Login success: ${email} (${user.role})`);
  res.json({ token, role: user.role, email: user.email });
});

// ── 12. ADMIN — LOGIN HISTORY ─────────────────────────────────────────────────
// GET /api/admin/history
// Returns all login logs, newest first. Requires valid JWT with role === 'admin'.

app.get('/api/admin/history', requireAuth, requireAdmin, async (_req, res) => {
  try {
    const logs = await LoginLog.find().sort({ timestamp: -1 }).lean();
    res.json(logs);
  } catch (err) {
    console.error('[admin] DB query error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve history.' });
  }
});

// ── 13. CSV PROXY ─────────────────────────────────────────────────────────────
const FETCH_TIMEOUT_MS = 15_000;

app.get('/api/bookings', async (_req, res) => {
  const csvUrl = process.env.CSV_SOURCE_URL;

  if (!csvUrl) {
    console.error('[proxy] CSV_SOURCE_URL is not set');
    return res.status(500).json({ error: 'Server misconfiguration: CSV_SOURCE_URL environment variable is missing.' });
  }

  const controller = new AbortController();
  const timer      = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const upstream = await fetch(csvUrl, {
      signal:  controller.signal,
      headers: {
        'User-Agent': 'TicketEx-Proxy/1.0',
        'Accept':     'text/csv, text/plain, */*',
      },
    });

    clearTimeout(timer);

    if (!upstream.ok) {
      console.error(`[proxy] upstream ${upstream.status} for ${csvUrl}`);
      return res.status(upstream.status).json({ error: `Upstream returned HTTP ${upstream.status}.` });
    }

    const csvText = await upstream.text();
    res.setHeader('Content-Type',  'text/csv; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('X-Rows-Fetched', csvText.split('\n').length - 1);

    console.log(`[proxy] served ${csvText.length} bytes`);
    res.send(csvText);

  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') return res.status(504).json({ error: 'Upstream timed out.' });
    console.error('[proxy] fetch error:', err.message);
    res.status(502).json({ error: 'Failed to reach the upstream data source.' });
  }
});

// ── 14. 404 & ERROR HANDLERS ──────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Not found.' }));

app.use((err, _req, res, _next) => {
  console.error('[error]', err.message);
  res.status(403).json({ error: err.message });
});

// ── 15. START + GRACEFUL SHUTDOWN ─────────────────────────────────────────────
const server = app.listen(PORT, () => {
  console.log(`[startup] TicketEx server running on port ${PORT}`);
  console.log(`[startup] Allowed origins: ${ALLOWED_ORIGINS.join(', ')}`);
});

function shutdown(signal) {
  console.log(`[shutdown] ${signal} received — closing server`);
  server.close(async () => {
    await mongoose.connection.close();
    console.log('[shutdown] All connections closed. Exiting.');
    process.exit(0);
  });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
