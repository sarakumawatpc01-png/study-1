const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const https = require('https');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const db = require('../db');
const { authRequired } = require('../middleware/auth');
const { getRolePermissions } = require('../services/admin');

const router = express.Router();
const defaultLimiterMessage = { error: 'Too many requests. Please try again later.' };
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: defaultLimiterMessage,
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: defaultLimiterMessage,
});

const loginSignals = new Map();
const captchaChallenges = new Map();
const twoFactorChallenges = new Map();

const SOFT_WINDOW_MS = 15 * 60 * 1000;
const CAPTCHA_AFTER_FAILURES = 3;
const TWO_FACTOR_AFTER_FAILURES = 5;
const CAPTCHA_TTL_MS = 5 * 60 * 1000;
const TWO_FACTOR_TTL_MS = 5 * 60 * 1000;
const DEFAULT_PLATFORM_LANGUAGE = 'English';
const DEFAULT_TEST_LANGUAGE = 'English';
const SIGNUP_WEBHOOK_TIMEOUT_MS = 3000;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function clientIp(req) {
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

function signalKey(req, email) {
  return `${String(email || '').toLowerCase()}|${clientIp(req)}`;
}

function getSignal(req, email) {
  const key = signalKey(req, email);
  const now = Date.now();
  const existing = loginSignals.get(key);
  if (!existing || now - existing.lastFailureAt > SOFT_WINDOW_MS) {
    const fresh = { failures: 0, lastFailureAt: 0 };
    loginSignals.set(key, fresh);
    return fresh;
  }
  return existing;
}

function registerFailure(req, email) {
  const signal = getSignal(req, email);
  signal.failures += 1;
  signal.lastFailureAt = Date.now();
  return signal;
}

function clearFailures(req, email) {
  loginSignals.delete(signalKey(req, email));
}

function makeCaptchaChallenge() {
  const a = crypto.randomInt(2, 10);
  const b = crypto.randomInt(2, 10);
  const token = `cap_${crypto.randomUUID()}`;
  captchaChallenges.set(token, { answer: String(a + b), expiresAt: Date.now() + CAPTCHA_TTL_MS });
  return { token, question: `${a} + ${b} = ?` };
}

function checkCaptcha(token, answer) {
  const row = captchaChallenges.get(String(token || ''));
  if (!row) return false;
  if (row.expiresAt <= Date.now()) {
    captchaChallenges.delete(String(token || ''));
    return false;
  }
  const ok = String(answer || '').trim() === row.answer;
  if (ok) captchaChallenges.delete(String(token || ''));
  return ok;
}

function makeTwoFactorChallenge(user, signalMeta) {
  const code = String(crypto.randomInt(100000, 1000000));
  const token = `tfa_${crypto.randomUUID()}`;
  twoFactorChallenges.set(token, {
    code,
    userId: user.id,
    email: user.email,
    expiresAt: Date.now() + TWO_FACTOR_TTL_MS,
    key: signalMeta?.key || '',
  });
  return { token, code };
}

function issueToken(user) {
  return jwt.sign({ userId: user.id, email: user.email, tokenVersion: Number(user.token_version || 0) }, process.env.JWT_SECRET, {
    expiresIn: '7d',
  });
}

function notifyAdminsOnSignup(user) {
  try {
    const admins = db
      .prepare("SELECT id FROM users WHERE role IN ('admin','superadmin') AND is_active = 1")
      .all();
    if (!admins.length) return;
    const now = new Date().toISOString();
    const title = '🆕 New user signup';
    const body = `${user.name} (${user.email}) signed up for ${user.exam}.`;
    const stmt = db.prepare('INSERT INTO notifications (user_id, title, body, created_at) VALUES (?, ?, ?, ?)');
    for (const admin of admins) {
      stmt.run(admin.id, title, body, now);
    }
  } catch (_err) {}
}

function sendSignupAlertWebhook(user) {
  const webhookUrl = String(process.env.SIGNUP_ALERT_WEBHOOK_URL || '').trim();
  if (!webhookUrl) return;
  try {
    const parsed = new URL(webhookUrl);
    if (parsed.protocol !== 'https:') return;
    const payload = JSON.stringify({
      event: 'user.signup',
      user: { id: user.id, email: user.email, name: user.name, exam: user.exam },
      occurred_at: new Date().toISOString(),
    });
    const req = https.request(webhookUrl, {
      method: 'POST',
      timeout: SIGNUP_WEBHOOK_TIMEOUT_MS,
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) },
    });
    req.on('error', (err) => {
      if (process.env.NODE_ENV !== 'production') console.warn('signup webhook error:', err?.message || 'unknown');
    });
    req.on('timeout', () => {
      if (process.env.NODE_ENV !== 'production') console.warn('signup webhook timeout');
      req.destroy();
    });
    req.write(payload);
    req.end();
  } catch (_err) {}
}

const signupSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().min(2),
  exam: z.string().min(2),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
  captcha_token: z.string().optional(),
  captcha_answer: z.string().optional(),
});

const verifyTwoFactorSchema = z.object({
  two_factor_token: z.string().min(1),
  code: z.string().min(4).max(8),
});

router.post('/signup', authLimiter, async (req, res) => {
  const parsed = signupSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid input' });

  const { email, password, name, exam } = parsed.data;
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(409).json({ error: 'Email already exists' });

  const passwordHash = await bcrypt.hash(password, 10);
  const createdAt = new Date().toISOString();

  const tx = db.transaction(() => {
    const result = db
      .prepare(
        'INSERT INTO users (email, password_hash, name, exam, platform_language, test_language, role, is_active, token_version, mfa_enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, 0, ?)'
      )
      .run(email, passwordHash, name, exam, DEFAULT_PLATFORM_LANGUAGE, DEFAULT_TEST_LANGUAGE, 'student', createdAt);
    db.prepare('INSERT INTO profiles (user_id, mood, readiness_score) VALUES (?, ?, ?)')
      .run(result.lastInsertRowid, 'Normal / Okay', 50);
    return result.lastInsertRowid;
  });

  const userId = tx();
  notifyAdminsOnSignup({ id: userId, email, name, exam });
  sendSignupAlertWebhook({ id: userId, email, name, exam });
  const token = issueToken({ id: userId, email, token_version: 0 });
  res.status(201).json({ token, user: { id: userId, email, name, exam } });
});

router.post('/login', loginLimiter, async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid input' });

  const { email, password, captcha_token: captchaToken, captcha_answer: captchaAnswer } = parsed.data;
  const signal = getSignal(req, email);
  const shouldChallengeCaptcha = signal.failures >= CAPTCHA_AFTER_FAILURES;
  const hasValidCaptcha = !shouldChallengeCaptcha || checkCaptcha(captchaToken, captchaAnswer);
  if (!hasValidCaptcha) {
    const captcha = makeCaptchaChallenge();
    return res.status(400).json({
      error: 'Captcha required',
      warning: 'Multiple attempts detected. Please verify you are human to continue.',
      captchaRequired: true,
      captcha,
    });
  }

  const user = db
    .prepare('SELECT id, email, name, exam, role, package_name, platform_language, test_language, password_hash, token_version, is_active FROM users WHERE email = ?')
    .get(email);
  if (!user) {
    const updated = registerFailure(req, email);
    await sleep(Math.min(2 ** Math.min(updated.failures, 6) * 120, 5000));
    const captcha = updated.failures >= CAPTCHA_AFTER_FAILURES ? makeCaptchaChallenge() : null;
    return res.status(401).json({
      error: 'Invalid credentials',
      warning: updated.failures >= CAPTCHA_AFTER_FAILURES
        ? 'Security check enabled after repeated incorrect passwords.'
        : 'Incorrect email or password.',
      captchaRequired: Boolean(captcha),
      ...(captcha ? { captcha } : {}),
    });
  }

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    const updated = registerFailure(req, email);
    await sleep(Math.min(2 ** Math.min(updated.failures, 6) * 120, 5000));
    const captcha = updated.failures >= CAPTCHA_AFTER_FAILURES ? makeCaptchaChallenge() : null;
    return res.status(401).json({
      error: 'Invalid credentials',
      warning: updated.failures >= CAPTCHA_AFTER_FAILURES
        ? 'Security check enabled after repeated incorrect passwords.'
        : 'Incorrect email or password.',
      captchaRequired: Boolean(captcha),
      ...(captcha ? { captcha } : {}),
    });
  }

  if (signal.failures >= TWO_FACTOR_AFTER_FAILURES) {
    const challenge = makeTwoFactorChallenge(user, { key: signalKey(req, email) });
    return res.status(202).json({
      requiresTwoFactor: true,
      twoFactorToken: challenge.token,
      message: 'Additional verification required for your safety.',
      ...(process.env.NODE_ENV !== 'production' ? { demoCode: challenge.code } : {}),
    });
  }

  if (Number(user.is_active) !== 1) return res.status(403).json({ error: 'Account disabled by admin' });
  const token = issueToken(user);
  db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(new Date().toISOString(), user.id);
  clearFailures(req, email);
  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      exam: user.exam,
      role: user.role,
      package_name: user.package_name || 'free',
      platform_language: user.platform_language || DEFAULT_PLATFORM_LANGUAGE,
      test_language: user.test_language || DEFAULT_TEST_LANGUAGE,
    },
  });
});

router.post('/verify-2fa', loginLimiter, async (req, res) => {
  const parsed = verifyTwoFactorSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid input' });

  const { two_factor_token: token, code } = parsed.data;
  const challenge = twoFactorChallenges.get(token);
  if (!challenge) return res.status(400).json({ error: 'Verification expired. Please login again.' });
  if (challenge.expiresAt <= Date.now()) {
    twoFactorChallenges.delete(token);
    return res.status(400).json({ error: 'Verification expired. Please login again.' });
  }
  if (String(code).trim() !== challenge.code) return res.status(401).json({ error: 'Invalid verification code' });

  const user = db.prepare(
    'SELECT id, email, name, exam, role, package_name, platform_language, test_language, token_version, is_active FROM users WHERE id = ?'
  ).get(challenge.userId);
  twoFactorChallenges.delete(token);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (Number(user.is_active) !== 1) return res.status(403).json({ error: 'Account disabled by admin' });

  const signed = issueToken(user);
  db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(new Date().toISOString(), user.id);
  if (challenge.key) loginSignals.delete(challenge.key);
  res.json({
    token: signed,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      exam: user.exam,
      role: user.role,
      package_name: user.package_name || 'free',
      platform_language: user.platform_language || DEFAULT_PLATFORM_LANGUAGE,
      test_language: user.test_language || DEFAULT_TEST_LANGUAGE,
    },
  });
});

setInterval(() => {
  const now = Date.now();
  for (const [key, signal] of loginSignals.entries()) {
    if (now - signal.lastFailureAt > SOFT_WINDOW_MS) loginSignals.delete(key);
  }
  for (const [token, row] of captchaChallenges.entries()) {
    if (row.expiresAt <= now) captchaChallenges.delete(token);
  }
  for (const [token, row] of twoFactorChallenges.entries()) {
    if (row.expiresAt <= now) twoFactorChallenges.delete(token);
  }
}, 60 * 1000).unref();

router.get('/me', authRequired, (req, res) => {
  const user = db
    .prepare(
      'SELECT u.id, u.email, u.name, u.exam, u.role, u.package_name, u.platform_language, u.test_language, p.mood, p.readiness_score AS readinessScore FROM users u JOIN profiles p ON p.user_id = u.id WHERE u.id = ?'
    )
    .get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ ...user, permissions: getRolePermissions(user.role || 'student') });
});

module.exports = router;
