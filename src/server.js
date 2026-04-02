require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');
const db = require('./db');

const authApi = require('./api/auth');
const tasksApi = require('./api/tasks');
const analyticsApi = require('./api/analytics');
const profileApi = require('./api/profile');
const miscApi = require('./api/misc');

const RELEASE_CACHE_TTL_MS = 3000;
const releaseControlCache = {
  loadedAt: 0,
  maintenanceMode: false,
  killSwitch: false,
};

function getReleaseControls() {
  const now = Date.now();
  if (now - releaseControlCache.loadedAt < RELEASE_CACHE_TTL_MS) return releaseControlCache;
  try {
    const rows = db.prepare('SELECT control_key, enabled FROM release_controls').all();
    releaseControlCache.maintenanceMode = rows.some((r) => r.control_key === 'maintenance_mode' && Number(r.enabled) === 1);
    releaseControlCache.killSwitch = rows.some((r) => r.control_key === 'global_kill_switch' && Number(r.enabled) === 1);
  } catch (_err) {
    releaseControlCache.maintenanceMode = false;
    releaseControlCache.killSwitch = false;
  }
  releaseControlCache.loadedAt = now;
  return releaseControlCache;
}

if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET is required. Set it in environment variables or .env file.');
}
const isProduction = String(process.env.NODE_ENV || '').toLowerCase() === 'production';
if (isProduction) {
  if (!process.env.AUDIT_SIGNING_SECRET) {
    throw new Error('AUDIT_SIGNING_SECRET is required in production.');
  }
  if (!process.env.PAYMENT_CONFIG_ENCRYPTION_KEY) {
    throw new Error('PAYMENT_CONFIG_ENCRYPTION_KEY is required in production.');
  }
}

function parseAllowlist(raw) {
  return String(raw || '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);
}

function parseTrustProxy(raw) {
  const value = String(raw || '').trim().toLowerCase();
  if (!value) return 'loopback';
  if (value === 'true') return true;
  if (value === 'false') return false;
  if (/^\d+$/.test(value)) return Number(value);
  return raw;
}

const corsAllowedOrigins = parseAllowlist(process.env.CORS_ALLOWED_ORIGINS);
if (isProduction && corsAllowedOrigins.length === 0) {
  throw new Error('CORS_ALLOWED_ORIGINS is required in production and must include one or more origins.');
}

const app = express();
app.set('trust proxy', parseTrustProxy(process.env.TRUST_PROXY));
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com'],
        scriptSrcAttr: ["'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
      },
    },
  })
);
app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      if (!isProduction) return callback(null, true);
      if (corsAllowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error('Not allowed by CORS'));
    },
  })
);
const jsonLimit = String(process.env.JSON_BODY_LIMIT || '1mb');
app.use(express.json({ limit: jsonLimit }));
morgan.token('safe-url', (req) => req.path || '/');
app.use(morgan(':remote-addr - :remote-user [:date[clf]] ":method :safe-url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent"'));
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please try again later.' },
  })
);

app.use((req, res, next) => {
  const controls = getReleaseControls();
  const started = Date.now();
  res.on('finish', () => {
    try {
      if (controls.killSwitch) return;
      db.prepare(
        'INSERT INTO api_request_logs (user_id, method, endpoint, status_code, latency_ms, source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
      ).run(req.user?.id || null, req.method, req.path, res.statusCode, Date.now() - started, 'app', new Date().toISOString());
    } catch (_err) {
      // no-op
    }
  });
  next();
});

app.use((req, res, next) => {
  const controls = getReleaseControls();
  if (controls.maintenanceMode && req.path !== '/health' && !req.path.startsWith('/api/auth')) {
    return res.status(503).json({ error: 'Maintenance mode enabled' });
  }
  if (controls.killSwitch && req.path !== '/health') {
    return res.status(503).json({ error: 'Service temporarily disabled' });
  }
  return next();
});

app.get('/health', (_req, res) => res.json({ ok: true, service: 'study-app' }));

app.use('/api/auth', authApi);
app.use('/api/tasks', tasksApi);
app.use('/api/analytics', analyticsApi);
app.use('/api/profile', profileApi);
app.use('/api', miscApi);

app.use(express.static(path.join(process.cwd(), 'public')));
app.get('*', (_req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'index.html'));
});

const port = Number(process.env.PORT || 3000);
if (require.main === module) {
  const server = app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`Server running on http://localhost:${port}`);
  });

  const GRACEFUL_SHUTDOWN_TIMEOUT_MS = 10000;
  let shuttingDown = false;
  function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    // eslint-disable-next-line no-console
    console.log(`Received ${signal}. Shutting down gracefully...`);
    const forceClose = setTimeout(() => {
      // eslint-disable-next-line no-console
      console.error('Force exiting after shutdown timeout');
      process.exit(1);
    }, GRACEFUL_SHUTDOWN_TIMEOUT_MS);
    server.close(() => {
      clearTimeout(forceClose);
      process.exit(0);
    });
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

module.exports = app;
