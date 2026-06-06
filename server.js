// =============================================================================
// TicketEx Proxy + Auth Server
//
// Required environment variables (Render dashboard → Environment):
//   CSV_SOURCE_URL  — CORS-blocked CSV URL
//   FRONTEND_URL    — Vercel URL(s), comma-separated
//   JWT_SECRET      — long random string for signing tokens
//   MONGODB_URI     — MongoDB Atlas connection string
//
// Render automatically injects PORT — do not set it manually.
// =============================================================================

'use strict';

const express  = require('express');
const cors     = require('cors');
const fetch    = require('node-fetch');
const jwt      = require('jsonwebtoken');
const bcrypt   = require('bcryptjs');
const mongoose = require('mongoose');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── 1. MONGOOSE ───────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('[db] Connected to MongoDB'))
  .catch(err => console.error('[db] Connection error:', err.message));

const LoginLog = mongoose.model('LoginLog', new mongoose.Schema({
  email:     { type: String, required: true },
  role:      { type: String, required: true },
  timestamp: { type: Date,   default: Date.now },
}));

// Generic key/value flags (e.g. the "corgi mode" dashboard easter egg).
const Setting = mongoose.model('Setting', new mongoose.Schema({
  key:   { type: String, required: true, unique: true },
  value: { type: mongoose.Schema.Types.Mixed },
}));

// ── 2. USERS ──────────────────────────────────────────────────────────────────
// Passwords are bcrypt hashes. Generate a new hash:
//   node -e "require('bcryptjs').hash('yourpassword', 10).then(console.log)"
//
// IMPORTANT: Run that command locally, paste the hash here, never store plain text.
const USERS = [
  {
    email:    'vishalratnakar453@gmail.com',
    role:     'admin',
    passhash: process.env.ADMIN_PASS_HASH,   // set in Render environment
  },
  {
    email:    'yogesh.parashar@ticketex.co',
    role:     'employee',
    passhash: process.env.EMP1_PASS_HASH,
  },
];

// ── 3. CORS ───────────────────────────────────────────────────────────────────
const PROD_ORIGINS = (process.env.FRONTEND_URL || '')
  .split(',').map(o => o.trim()).filter(Boolean);

const DEV_ORIGINS = [
  'http://127.0.0.1:5500', 'http://localhost:5500',
  'http://127.0.0.1:5501', 'http://localhost:5501',
  'http://127.0.0.1:3000', 'http://localhost:3000',
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

// ── 4. SECURITY HEADERS & BODY PARSING ───────────────────────────────────────
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options',        'DENY');
  next();
});
app.use(express.json());

// ── 5. AUTH MIDDLEWARE ────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token.' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin')
    return res.status(403).json({ error: 'Forbidden: admin access only.' });
  next();
}

// ── 6. HEALTH CHECK ───────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({
    status:    'ok',
    timestamp: new Date().toISOString(),
    uptime:    Math.floor(process.uptime()),
    db:        mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
  });
});

// ── 7. LOGIN ──────────────────────────────────────────────────────────────────
// POST /api/auth/login   body: { email, password }

app.post('/api/auth/login', async (req, res) => {
  const email    = (req.body.email    || '').toLowerCase().trim();
  const password = (req.body.password || '').trim();

  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required.' });

  const user = USERS.find(u => u.email.toLowerCase() === email);

  // Always run bcrypt compare to prevent timing attacks
  const dummyHash = '$2a$10$dummyhashfordummycomparison000000000000000000000000000';
  const hash      = user?.passhash || dummyHash;
  const match     = await bcrypt.compare(password, hash);

  if (!user || !match)
    return res.status(401).json({ error: 'Incorrect email or password.' });

  const token = jwt.sign(
    { email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '8h' }
  );

  try {
    await LoginLog.create({ email: user.email, role: user.role });
  } catch (dbErr) {
    console.error('[db] Failed to save login log:', dbErr.message);
  }

  console.log(`[auth] Login: ${email} (${user.role})`);
  res.json({ token, role: user.role, email: user.email });
});

// ── 8. ADMIN — LOGIN HISTORY ──────────────────────────────────────────────────
app.get('/api/admin/history', requireAuth, requireAdmin, async (_req, res) => {
  try {
    const logs = await LoginLog.find().sort({ timestamp: -1 }).lean();
    res.json(logs);
  } catch (err) {
    console.error('[admin] DB query error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve history.' });
  }
});

// ── 8b. SETTINGS (feature flags) ──────────────────────────────────────────────
// Any logged-in user reads the current flags (the dashboard polls this).
app.get('/api/settings', requireAuth, async (_req, res) => {
  try {
    const doc = await Setting.findOne({ key: 'corgiMode' }).lean();
    res.json({ corgiMode: !!(doc && doc.value) });
  } catch (err) {
    console.error('[settings] read error:', err.message);
    res.status(500).json({ error: 'Failed to read settings.' });
  }
});

// Only admins flip the flags (the admin panel toggle posts here).
app.post('/api/admin/settings', requireAuth, requireAdmin, async (req, res) => {
  const enabled = !!req.body.corgiMode;
  try {
    await Setting.findOneAndUpdate(
      { key: 'corgiMode' },
      { key: 'corgiMode', value: enabled },
      { upsert: true, new: true }
    );
    console.log(`[settings] corgiMode set to ${enabled} by ${req.user.email}`);
    res.json({ corgiMode: enabled });
  } catch (err) {
    console.error('[settings] write error:', err.message);
    res.status(500).json({ error: 'Failed to update settings.' });
  }
});

// ── 9. CSV PROXY ──────────────────────────────────────────────────────────────
const FETCH_TIMEOUT_MS = 15_000;

app.get('/api/bookings', async (_req, res) => {
  const csvUrl = process.env.CSV_SOURCE_URL;
  if (!csvUrl) return res.status(500).json({ error: 'CSV_SOURCE_URL is not set.' });

  const controller = new AbortController();
  const timer      = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const upstream = await fetch(csvUrl, {
      signal:  controller.signal,
      headers: { 'User-Agent': 'TicketEx-Proxy/1.0', 'Accept': 'text/csv, */*' },
    });
    clearTimeout(timer);

    if (!upstream.ok) return res.status(upstream.status).json({ error: `Upstream returned ${upstream.status}.` });

    const csvText = await upstream.text();
    res.setHeader('Content-Type',   'text/csv; charset=utf-8');
    res.setHeader('Cache-Control',  'no-store, no-cache, must-revalidate');
    res.setHeader('X-Rows-Fetched', csvText.split('\n').length - 1);
    res.send(csvText);

  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') return res.status(504).json({ error: 'Upstream timed out.' });
    res.status(502).json({ error: 'Failed to reach the upstream data source.' });
  }
});

// ── 10. 404 & ERROR HANDLERS ──────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((err, _req, res, _next) => {
  console.error('[error]', err.message);
  res.status(403).json({ error: err.message });
});

// ── 11. START + GRACEFUL SHUTDOWN ─────────────────────────────────────────────
const server = app.listen(PORT, () => {
  console.log(`[startup] TicketEx server on port ${PORT}`);
  console.log(`[startup] Allowed origins: ${ALLOWED_ORIGINS.join(', ')}`);
});

function shutdown(signal) {
  console.log(`[shutdown] ${signal} — closing`);
  server.close(async () => {
    await mongoose.connection.close();
    process.exit(0);
  });
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
