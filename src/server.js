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

if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET is required. Set it in environment variables or .env file.');
}

const app = express();
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
      },
    },
  })
);
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(morgan('combined'));
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.use((req, res, next) => {
  const started = Date.now();
  res.on('finish', () => {
    try {
      const release = db.prepare("SELECT enabled FROM release_controls WHERE control_key = 'global_kill_switch'").get();
      if (release && Number(release.enabled) === 1) return;
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
  const maintenance = db.prepare("SELECT enabled FROM release_controls WHERE control_key = 'maintenance_mode'").get();
  if (maintenance && Number(maintenance.enabled) === 1 && req.path !== '/health' && !req.path.startsWith('/api/auth')) {
    return res.status(503).json({ error: 'Maintenance mode enabled' });
  }
  const kill = db.prepare("SELECT enabled FROM release_controls WHERE control_key = 'global_kill_switch'").get();
  if (kill && Number(kill.enabled) === 1 && req.path !== '/health') {
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
  app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`Server running on http://localhost:${port}`);
  });
}

module.exports = app;
