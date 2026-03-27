require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const path = require('path');

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
