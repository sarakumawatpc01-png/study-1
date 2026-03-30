const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const bcrypt = require('bcryptjs');
const { z } = require('zod');
const db = require('../db');
const { authRequired } = require('../middleware/auth');
const {
  parseJsonSafe,
  requirePermission,
  createAuditLog,
  consumeElevatedAccessToken,
  requireElevatedAccess,
  requireDualApproval,
  getRolePermissions,
} = require('../services/admin');

const router = express.Router();
router.use(authRequired);

function inferQuestionBug(description, title = '') {
  const text = `${title} ${description}`.toLowerCase();
  if (/\b(option|correct answer|wrong answer|multiple correct)\b/.test(text)) {
    return {
      summary: 'Likely answer-key mismatch detected by AI quick triage.',
      bug: 'Answer key mapping for this question may be incorrect or ambiguous.',
    };
  }
  if (/\b(typo|format|render|latex|equation)\b/.test(text)) {
    return {
      summary: 'Likely formatting/content presentation issue detected.',
      bug: 'Question text/options rendering or formatting likely contains an error.',
    };
  }
  if (/\b(unclear|ambiguous|confusing)\b/.test(text)) {
    return {
      summary: 'Likely ambiguity issue in question wording.',
      bug: 'Question statement is likely ambiguous and may allow multiple interpretations.',
    };
  }
  return {
    summary: 'AI quick triage could not confidently classify the exact issue.',
    bug: 'Needs manual expert review for root-cause classification.',
  };
}

function nowIso() {
  return new Date().toISOString();
}

function parseList(v) {
  return String(v || '')
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
}

function createApiKey() {
  const raw = `sk_${crypto.randomBytes(24).toString('hex')}`;
  const keyPrefix = raw.slice(0, 12);
  const keyHash = crypto.createHash('sha256').update(raw).digest('hex');
  return { raw, keyPrefix, keyHash };
}

function isSafeBackupPath(p) {
  return /^[a-zA-Z0-9_./-]+$/.test(String(p || ''));
}

const PAYMENT_CONFIG_KEY = 'payments.gateway';
const PAYMENT_CURRENCIES = ['INR', 'USD', 'EUR', 'GBP', 'AED', 'SGD'];
const CONNECTION_TEST_LIMIT_WINDOW_MS = 60 * 1000;
const CONNECTION_TEST_LIMIT_MAX = 5;
const CIRCUIT_BREAKER_FAIL_THRESHOLD = 3;
const CIRCUIT_BREAKER_OPEN_MS = 2 * 60 * 1000;
const WEBHOOK_TIMESTAMP_TOLERANCE_MS = 5 * 60 * 1000;
// Process-local guardrails; replace with shared storage (e.g. Redis) for multi-instance deployments.
const connectionTestBuckets = new Map();
const providerCircuitState = new Map();

function paymentEncryptionKey() {
  const base = String(process.env.PAYMENT_CONFIG_ENCRYPTION_KEY || process.env.JWT_SECRET || '');
  return crypto.createHash('sha256').update(base).digest();
}

function encryptPaymentSecrets(raw) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', paymentEncryptionKey(), iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(raw), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    encrypted: true,
    alg: 'aes-256-gcm',
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    data: data.toString('base64'),
    version: 1,
  };
}

function decryptPaymentSecrets(raw) {
  try {
    const obj = typeof raw === 'string' ? parseJsonSafe(raw, {}) : (raw || {});
    if (!obj?.encrypted) return obj;
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      paymentEncryptionKey(),
      Buffer.from(String(obj.iv || ''), 'base64')
    );
    decipher.setAuthTag(Buffer.from(String(obj.tag || ''), 'base64'));
    const plain = Buffer.concat([
      decipher.update(Buffer.from(String(obj.data || ''), 'base64')),
      decipher.final(),
    ]).toString('utf8');
    return parseJsonSafe(plain, {});
  } catch (_err) {
    // eslint-disable-next-line no-console
    console.error('Payment secret decrypt failed');
    return {};
  }
}

function externalSecretManagerEnabled() {
  return String(process.env.PAYMENT_SECRET_MANAGER || '').toLowerCase() === 'env';
}

function resolveExternalPaymentSecret(ref) {
  if (!externalSecretManagerEnabled()) return null;
  const envKey = `PAYMENT_SECRET_REF_${String(ref || '').trim()}`;
  const raw = process.env[envKey];
  return parseJsonSafe(raw, null);
}

function hydratePaymentSecrets(cfg) {
  if (!cfg?.managed_externally || !cfg?.external_secret_ref) return cfg || {};
  const ext = resolveExternalPaymentSecret(cfg.external_secret_ref) || {};
  return {
    ...cfg,
    key_id: ext.key_id || cfg.key_id || '',
    key_secret: ext.key_secret || '',
    webhook_secret: ext.webhook_secret || '',
  };
}

function maskValue(v) {
  const s = String(v || '').trim();
  if (!s) return null;
  if (s.length <= 6) return '••••••';
  return `${s.slice(0, 3)}••••••${s.slice(-2)}`;
}

function maskedPaymentSettings(raw) {
  const cfg = hydratePaymentSecrets(decryptPaymentSecrets(raw));
  return {
    provider: cfg.provider || null,
    mode: cfg.mode || null,
    currency: cfg.currency || null,
    key_id: maskValue(cfg.key_id),
    key_secret: maskValue(cfg.key_secret),
    webhook_secret: maskValue(cfg.webhook_secret),
    has_key_id: Boolean(String(cfg.key_id || '').trim()),
    has_key_secret: Boolean(String(cfg.key_secret || '').trim()),
    has_webhook_secret: Boolean(String(cfg.webhook_secret || '').trim()),
    managed_externally: Boolean(cfg.managed_externally),
    external_secret_ref: cfg.managed_externally ? String(cfg.external_secret_ref || '') : null,
  };
}

function paymentSettingsSchema() {
  return z.object({
    provider: z.enum(['razorpay', 'stripe', 'cashfree']),
    mode: z.enum(['test', 'live']),
    currency: z.enum(PAYMENT_CURRENCIES),
    key_id: z.string().min(6).max(150),
    key_secret: z.string().min(8).max(200),
    webhook_secret: z.string().max(200).optional().nullable(),
  }).superRefine((v, ctx) => {
    if (v.provider === 'razorpay' && !/^rzp_(test|live)_[A-Za-z0-9]+$/.test(v.key_id)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['key_id'], message: 'Invalid Razorpay key id format' });
    }
    if (v.provider === 'stripe') {
      if (!/^pk_(test|live)_[A-Za-z0-9]+$/.test(v.key_id)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['key_id'], message: 'Invalid Stripe publishable key format' });
      }
      if (!/^sk_(test|live)_[A-Za-z0-9]+$/.test(v.key_secret)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['key_secret'], message: 'Invalid Stripe secret key format' });
      }
    }
    if (v.provider === 'razorpay') {
      const expected = v.mode === 'live' ? 'rzp_live_' : 'rzp_test_';
      if (!v.key_id.startsWith(expected)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['mode'], message: 'Mode does not match Razorpay key prefix' });
      }
    }
    if (v.provider === 'stripe') {
      const expectedPk = v.mode === 'live' ? 'pk_live_' : 'pk_test_';
      const expectedSk = v.mode === 'live' ? 'sk_live_' : 'sk_test_';
      if (!v.key_id.startsWith(expectedPk) || !v.key_secret.startsWith(expectedSk)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['mode'], message: 'Mode does not match Stripe key prefixes' });
      }
    }
  });
}

function externalPaymentSettingsSchema() {
  return z.object({
    provider: z.enum(['razorpay', 'stripe', 'cashfree']),
    mode: z.enum(['test', 'live']),
    currency: z.enum(PAYMENT_CURRENCIES),
    external_secret_ref: z.string().min(3).max(120),
  });
}

function requestJson({ hostname, path: requestPath, method = 'GET', headers = {}, timeoutMs = 5000 }) {
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname, path: requestPath, method, headers }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        resolve({ statusCode: res.statusCode || 0, body: data });
      });
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => req.destroy(new Error('Connection timeout')));
    req.end();
  });
}

function assertConnectionRateLimit(userId) {
  const now = Date.now();
  const key = String(userId || 'anon');
  const items = (connectionTestBuckets.get(key) || []).filter((t) => now - t < CONNECTION_TEST_LIMIT_WINDOW_MS);
  if (items.length >= CONNECTION_TEST_LIMIT_MAX) {
    return { ok: false, error: 'Too many payment connection tests. Try again in a minute.' };
  }
  items.push(now);
  connectionTestBuckets.set(key, items);
  return { ok: true };
}

function circuitKey(provider, mode) {
  return `${provider || 'unknown'}:${mode || 'unknown'}`;
}

function isCircuitOpen(provider, mode) {
  const state = providerCircuitState.get(circuitKey(provider, mode));
  if (!state) return false;
  if (state.openUntil && state.openUntil > Date.now()) return true;
  if (state.openUntil && state.openUntil <= Date.now()) {
    providerCircuitState.delete(circuitKey(provider, mode));
  }
  return false;
}

function updateCircuitState(provider, mode, success) {
  const key = circuitKey(provider, mode);
  const current = providerCircuitState.get(key) || { failures: 0, openUntil: 0 };
  if (success) {
    providerCircuitState.set(key, { failures: 0, openUntil: 0 });
    return;
  }
  const failures = Number(current.failures || 0) + 1;
  const openUntil = failures >= CIRCUIT_BREAKER_FAIL_THRESHOLD ? Date.now() + CIRCUIT_BREAKER_OPEN_MS : 0;
  providerCircuitState.set(key, { failures, openUntil });
}

function appendWebhookTransition({ webhookEventId, fromStatus, toStatus, reason, changedBy }) {
  db.prepare(
    'INSERT INTO webhook_event_transitions (webhook_event_id, from_status, to_status, reason, changed_by, changed_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(webhookEventId, fromStatus || null, toStatus, reason || null, changedBy || null, nowIso());
}

function normalizeSig(v) {
  return String(v || '').replace(/^sha256=/i, '').trim();
}

function safeTimingEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function userSummaryById(userId) {
  const user = db.prepare('SELECT id, email, name, exam, role, is_active, created_at, last_login_at FROM users WHERE id = ?').get(userId);
  if (!user) return null;
  const tasks = db.prepare(
    `SELECT status, COUNT(*) AS count FROM tasks WHERE user_id = ? GROUP BY status`
  ).all(userId);
  const moods = db.prepare('SELECT mood, note, created_at FROM moods WHERE user_id = ? ORDER BY created_at DESC LIMIT 20').all(userId);
  const mockTests = db.prepare('SELECT id, name, score, total, created_at FROM mock_tests WHERE user_id = ? ORDER BY created_at DESC LIMIT 20').all(userId);
  const reports = db.prepare('SELECT id, category, status, title, created_at, updated_at FROM reports WHERE user_id = ? ORDER BY created_at DESC LIMIT 20').all(userId);
  const notifications = db.prepare('SELECT id, title, body, read_flag, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 20').all(userId);
  return { user, tasks, moods, mockTests, reports, notifications };
}

router.get('/notifications', (req, res) => {
  const rows = db
    .prepare('SELECT id, title, body, read_flag, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50')
    .all(req.user.id);
  res.json(rows);
});

router.post('/notifications', (req, res) => {
  const schema = z.object({ title: z.string().min(1), body: z.string().min(1) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid notification payload' });
  try {
    db.prepare('INSERT INTO notifications (user_id, title, body, created_at) VALUES (?, ?, ?, ?)')
      .run(req.user.id, parsed.data.title, parsed.data.body, nowIso());
    res.status(201).json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to save notification' });
  }
});

router.get('/mock-tests', (req, res) => {
  const tests = db
    .prepare('SELECT id, name, score, total, created_at FROM mock_tests WHERE user_id = ? ORDER BY created_at DESC')
    .all(req.user.id);
  res.json(tests);
});

router.post('/mock-tests', (req, res) => {
  const schema = z.object({
    name: z.string().min(1),
    score: z.number().int().nonnegative(),
    total: z.number().int().positive(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid mock test payload' });
  try {
    db.prepare('INSERT INTO mock_tests (user_id, name, score, total, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(req.user.id, parsed.data.name, parsed.data.score, parsed.data.total, nowIso());
    res.status(201).json({ ok: true });
  } catch (_e) {
    res.status(500).json({ error: 'Failed to save mock test' });
  }
});

router.get('/error-journal', (req, res) => {
  const rows = db
    .prepare('SELECT * FROM error_journal WHERE user_id = ? ORDER BY created_at DESC')
    .all(req.user.id);
  res.json(rows);
});

router.post('/error-journal', (req, res) => {
  const schema = z.object({
    topic: z.string().min(1),
    question: z.string().min(1),
    your_answer: z.string().optional().nullable(),
    correct_answer: z.string().min(1),
    explanation: z.string().min(1),
    next_review_at: z.string().optional().nullable(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid error-journal payload' });
  const p = parsed.data;
  try {
    db.prepare(
      'INSERT INTO error_journal (user_id, topic, question, your_answer, correct_answer, explanation, next_review_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(req.user.id, p.topic, p.question, p.your_answer || null, p.correct_answer, p.explanation, p.next_review_at || null, nowIso());
    res.status(201).json({ ok: true });
  } catch (_e) {
    res.status(500).json({ error: 'Failed to save error-journal entry' });
  }
});

router.post('/reports', (req, res) => {
  const schema = z.object({
    category: z.enum(['question', 'content', 'technical', 'billing', 'general']).optional(),
    title: z.string().min(3).max(120),
    description: z.string().min(8).max(2000),
    priority: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid report payload' });
  const now = nowIso();
  const isQuestion = (parsed.data.category || 'general') === 'question';
  const triage = isQuestion ? inferQuestionBug(parsed.data.description, parsed.data.title) : null;
  const due = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString();
  const row = db.prepare(
    `INSERT INTO reports
     (user_id, category, title, description, ai_triage_status, ai_triage_summary, ai_triage_bug, priority, status, sla_due_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    req.user.id,
    parsed.data.category || 'general',
    parsed.data.title,
    parsed.data.description,
    isQuestion ? 'completed' : 'not_applicable',
    triage ? triage.summary : null,
    triage ? triage.bug : null,
    parsed.data.priority || 'medium',
    'open',
    due,
    now,
    now
  );
  createAuditLog({
    actor: req.user,
    action: 'report_create',
    targetType: 'report',
    targetId: row.lastInsertRowid,
    details: { category: parsed.data.category || 'general', priority: parsed.data.priority || 'medium' },
  });
  res.status(201).json({
    ok: true,
    id: row.lastInsertRowid,
    ai_triage: triage ? { status: 'completed', summary: triage.summary, bug: triage.bug } : null,
  });
});

router.get('/reports', (req, res) => {
  const mine = db
    .prepare(
      'SELECT id, category, title, description, priority, status, action_taken, admin_note, created_at, updated_at FROM reports WHERE user_id = ? ORDER BY created_at DESC'
    )
    .all(req.user.id);
  res.json(mine);
});

router.get('/admin/dashboard', requirePermission('dashboard:view'), (_req, res) => {
  const totalUsers = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  const activeToday = db.prepare("SELECT COUNT(DISTINCT user_id) AS c FROM task_events WHERE created_at >= datetime('now', '-1 day')").get().c;
  const newSignups = db.prepare("SELECT COUNT(*) AS c FROM users WHERE created_at >= datetime('now', '-1 day')").get().c;
  const totalTasks = db.prepare('SELECT COUNT(*) AS c FROM tasks').get().c;
  const completedTasks = db.prepare("SELECT COUNT(*) AS c FROM tasks WHERE status = 'completed'").get().c;
  const retention = totalUsers ? Number(((activeToday / totalUsers) * 100).toFixed(2)) : 0;
  const taskCompletion = totalTasks ? Number(((completedTasks / totalTasks) * 100).toFixed(2)) : 0;
  const api = db.prepare(
    `SELECT AVG(latency_ms) AS avgLatency,
      SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END) AS s5,
      COUNT(*) AS total
      FROM api_request_logs
      WHERE created_at >= datetime('now', '-1 day')`
  ).get();
  const ai = db.prepare(
    "SELECT COUNT(*) AS calls, COALESCE(SUM(cost_usd), 0) AS totalCost FROM ai_usage WHERE created_at >= datetime('now', '-1 day')"
  ).get();
  const failedCron = db.prepare(
    "SELECT COUNT(*) AS c FROM background_jobs WHERE status = 'failed'"
  ).get().c;
  const queuePending = db.prepare(
    "SELECT COUNT(*) AS c FROM reports WHERE status IN ('open','in_review')"
  ).get().c;
  const failedAiCalls = db.prepare(
    "SELECT COUNT(*) AS c FROM ai_usage WHERE status = 'failed' AND created_at >= datetime('now', '-1 day')"
  ).get().c;
  const apiSpike = db.prepare(
    "SELECT COUNT(*) AS c FROM api_request_logs WHERE created_at >= datetime('now', '-5 minutes')"
  ).get().c;
  const authAnomalies = db.prepare(
    "SELECT COUNT(*) AS c FROM audit_log WHERE action = 'auth_anomaly' AND created_at >= datetime('now', '-1 day')"
  ).get().c;
  res.json({
    kpis: {
      totalUsers,
      activeToday,
      newSignups,
      retentionPct: retention,
      taskCompletionPct: taskCompletion,
      apiLatencyMs: Number(api.avgLatency || 0),
      apiErrorRatePct: api.total ? Number((((api.s5 || 0) / api.total) * 100).toFixed(2)) : 0,
      aiUsageCalls: ai.calls || 0,
      aiCostUsd: Number(Number(ai.totalCost || 0).toFixed(6)),
    },
    systemHealth: {
      db: 'ok',
      queueStatus: queuePending > 100 ? 'degraded' : 'ok',
      backgroundJobs: failedCron > 0 ? 'degraded' : 'ok',
      failedCronJobs: failedCron,
    },
    alerts: {
      incidents: failedCron,
      failedAiCalls,
      apiSpikes: apiSpike > 500 ? apiSpike : 0,
      authAnomalies,
    },
  });
});

router.get('/admin/users', requirePermission('users:view'), (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  const exam = String(req.query.exam || '').trim();
  const status = String(req.query.status || '').trim();
  const role = String(req.query.role || '').trim();
  const base = db.prepare('SELECT id, email, name, exam, role, is_active, mfa_enabled, last_login_at, created_at FROM users ORDER BY created_at DESC').all();
  const filtered = base.filter((u) => {
    if (q && !`${u.email} ${u.name}`.toLowerCase().includes(q)) return false;
    if (exam && u.exam !== exam) return false;
    if (status === 'active' && Number(u.is_active) !== 1) return false;
    if (status === 'disabled' && Number(u.is_active) !== 0) return false;
    if (role && u.role !== role) return false;
    return true;
  });
  res.json(filtered);
});

router.get('/admin/users/:id', requirePermission('users:view'), (req, res) => {
  const summary = userSummaryById(Number(req.params.id));
  if (!summary) return res.status(404).json({ error: 'User not found' });
  res.json(summary);
});

router.post('/admin/users/:id/reset-password', requirePermission('users:edit'), requireElevatedAccess, (req, res) => {
  const schema = z.object({ new_password_hash: z.string().min(10) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid payload' });
  const r = db.prepare('UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?').run(parsed.data.new_password_hash, req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'User not found' });
  createAuditLog({ actor: req.user, action: 'user_reset_password', targetType: 'user', targetId: req.params.id, details: {} });
  res.json({ ok: true });
});

router.post('/admin/users/:id/force-logout', requirePermission('users:edit'), requireElevatedAccess, (req, res) => {
  const r = db.prepare('UPDATE users SET token_version = token_version + 1 WHERE id = ?').run(req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'User not found' });
  createAuditLog({ actor: req.user, action: 'user_force_logout', targetType: 'user', targetId: req.params.id, details: {} });
  res.json({ ok: true });
});

router.post('/admin/users/:id/disable', requirePermission('users:edit'), requireElevatedAccess, (req, res) => {
  const r = db.prepare('UPDATE users SET is_active = 0, token_version = token_version + 1 WHERE id = ?').run(req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'User not found' });
  createAuditLog({ actor: req.user, action: 'user_disable', targetType: 'user', targetId: req.params.id, details: {} });
  res.json({ ok: true });
});

router.post('/admin/users/:id/enable', requirePermission('users:edit'), (req, res) => {
  const r = db.prepare('UPDATE users SET is_active = 1 WHERE id = ?').run(req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'User not found' });
  createAuditLog({ actor: req.user, action: 'user_enable', targetType: 'user', targetId: req.params.id, details: {} });
  res.json({ ok: true });
});

router.post('/admin/users/:id/impersonate', requirePermission('users:edit'), requireElevatedAccess, (req, res) => {
  const user = db.prepare('SELECT id, email, name, exam, role FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  createAuditLog({ actor: req.user, action: 'user_impersonate', targetType: 'user', targetId: req.params.id, details: { actor: req.user.id } });
  res.json({ ok: true, impersonation: { userId: user.id, email: user.email, name: user.name, exam: user.exam, role: user.role } });
});

router.post('/admin/users/:id/delete', requirePermission('users:edit'), requireElevatedAccess, requireDualApproval('delete_user'), (req, res) => {
  const r = db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'User not found' });
  createAuditLog({ actor: req.user, action: 'user_delete', targetType: 'user', targetId: req.params.id, details: {} });
  res.json({ ok: true });
});

router.post('/admin/users/:id/anonymize', requirePermission('users:edit'), requireElevatedAccess, (req, res) => {
  const anon = `anon-${req.params.id}-${Date.now()}@deleted.local`;
  const r = db.prepare(
    "UPDATE users SET email = ?, name = 'Anonymized User', exam = 'N/A', is_active = 0, token_version = token_version + 1 WHERE id = ?"
  ).run(anon, req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'User not found' });
  createAuditLog({ actor: req.user, action: 'user_anonymize', targetType: 'user', targetId: req.params.id, details: {} });
  res.json({ ok: true });
});

router.post('/admin/users/bulk', requirePermission('users:edit'), (req, res) => {
  const schema = z.object({
    user_ids: z.array(z.number().int().positive()).min(1),
    action: z.enum(['notify', 'set_role', 'disable', 'enable', 'export']),
    role: z.string().optional(),
    title: z.string().optional(),
    body: z.string().optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid bulk payload' });
  const ids = parsed.data.user_ids;
  if (['set_role', 'disable'].includes(parsed.data.action)) {
    const consumed = consumeElevatedAccessToken(req.user.id, req.headers['x-elevated-token']);
    if (!consumed.ok) return res.status(403).json({ error: consumed.error });
  }
  if (parsed.data.action === 'set_role') {
    if (!parsed.data.role) return res.status(400).json({ error: 'role is required' });
    if (parsed.data.role === 'superadmin' && req.user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Only superadmin can assign superadmin role' });
    }
    db.prepare(`UPDATE users SET role = ? WHERE id IN (${ids.map(() => '?').join(',')})`).run(parsed.data.role, ...ids);
    for (const id of ids) {
      createAuditLog({
        actor: req.user,
        action: 'user_role_update',
        targetType: 'user',
        targetId: id,
        details: { role: parsed.data.role },
      });
    }
  } else if (parsed.data.action === 'disable') {
    db.prepare(`UPDATE users SET is_active = 0, token_version = token_version + 1 WHERE id IN (${ids.map(() => '?').join(',')})`).run(...ids);
  } else if (parsed.data.action === 'enable') {
    db.prepare(`UPDATE users SET is_active = 1 WHERE id IN (${ids.map(() => '?').join(',')})`).run(...ids);
  } else if (parsed.data.action === 'notify') {
    if (!parsed.data.title || !parsed.data.body) return res.status(400).json({ error: 'title and body are required' });
    const stmt = db.prepare('INSERT INTO notifications (user_id, title, body, created_at) VALUES (?, ?, ?, ?)');
    const insert = db.transaction(() => {
      for (const id of ids) stmt.run(id, parsed.data.title, parsed.data.body, nowIso());
    });
    insert();
  } else if (parsed.data.action === 'export') {
    const rows = db.prepare(`SELECT id, email, name, exam, role, is_active, created_at FROM users WHERE id IN (${ids.map(() => '?').join(',')})`).all(...ids);
    createAuditLog({ actor: req.user, action: 'users_bulk_export', targetType: 'user', targetId: 'bulk', details: { count: rows.length } });
    return res.json({ ok: true, users: rows });
  }
  createAuditLog({ actor: req.user, action: `users_bulk_${parsed.data.action}`, targetType: 'user', targetId: 'bulk', details: { count: ids.length } });
  res.json({ ok: true, affected: ids.length });
});

router.post('/admin/users/import', requirePermission('users:edit'), async (req, res) => {
  const schema = z.object({
    users: z.array(
      z.object({
        email: z.string().email(),
        name: z.string().min(2),
        exam: z.string().min(2),
        role: z.string().optional(),
      })
    ).min(1),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid payload' });
  const stmt = db.prepare(
    'INSERT OR IGNORE INTO users (email, password_hash, name, exam, role, is_active, token_version, mfa_enabled, created_at) VALUES (?, ?, ?, ?, ?, 1, 0, 0, ?)'
  );
  const prof = db.prepare('INSERT OR IGNORE INTO profiles (user_id, mood, readiness_score) VALUES (?, ?, ?)');
  let count = 0;
  const importedCredentials = [];
  for (const u of parsed.data.users) {
    const temporaryPassword = crypto.randomBytes(18).toString('hex');
    const temporaryHash = await bcrypt.hash(temporaryPassword, 10);
    const r = stmt.run(u.email, temporaryHash, u.name, u.exam, u.role || 'student', nowIso());
    if (r.changes) {
      count += 1;
      importedCredentials.push({ email: u.email, reset_required: true });
      prof.run(r.lastInsertRowid, 'Normal / Okay', 50);
    }
  }
  createAuditLog({ actor: req.user, action: 'users_import', targetType: 'user', targetId: 'bulk', details: { imported: count } });
  res.status(201).json({
    ok: true,
    imported: count,
    users: importedCredentials,
    note: 'Users are imported with random temporary passwords. Require secure password reset distribution out of band.',
  });
});

router.get('/admin/reports', requirePermission('reports:view'), (req, res) => {
  const statuses = parseList(req.query.status);
  const priorities = parseList(req.query.priority);
  const assignedTo = Number(req.query.assigned_to || 0);
  const rows = db
    .prepare(
      `SELECT r.id, r.user_id, u.email, u.name, r.category, r.title, r.description, r.ai_triage_status, r.ai_triage_summary, r.ai_triage_bug,
       r.priority, r.status, r.assigned_to, r.sla_due_at, r.resolution_template, r.action_taken, r.admin_note, r.internal_note, r.created_at, r.updated_at
       FROM reports r
       JOIN users u ON u.id = r.user_id
       ORDER BY r.created_at DESC`
    )
    .all()
    .filter((r) => (statuses.length ? statuses.includes(r.status) : true))
    .filter((r) => (priorities.length ? priorities.includes(r.priority) : true))
    .filter((r) => (assignedTo ? Number(r.assigned_to || 0) === assignedTo : true));
  res.json(rows);
});

router.post('/admin/reports/:id/action', requirePermission('reports:triage'), (req, res) => {
  const schema = z.object({
    status: z.enum(['open', 'in_review', 'resolved', 'closed', 'escalated']),
    action_taken: z.string().min(2).max(500),
    admin_note: z.string().max(1000).optional().nullable(),
    internal_note: z.string().max(2000).optional().nullable(),
    resolution_template: z.string().max(2000).optional().nullable(),
    assigned_to: z.number().int().positive().optional().nullable(),
    priority: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid admin action payload' });
  const existing = db.prepare('SELECT id FROM reports WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Report not found' });
  db.prepare(
    `UPDATE reports SET status = ?, action_taken = ?, admin_note = ?, internal_note = ?, resolution_template = ?,
     assigned_to = ?, priority = COALESCE(?, priority), updated_at = ? WHERE id = ?`
  ).run(
    parsed.data.status,
    parsed.data.action_taken,
    parsed.data.admin_note || null,
    parsed.data.internal_note || null,
    parsed.data.resolution_template || null,
    parsed.data.assigned_to || null,
    parsed.data.priority || null,
    nowIso(),
    req.params.id
  );
  createAuditLog({ actor: req.user, action: 'report_action', targetType: 'report', targetId: req.params.id, details: parsed.data });
  res.json({ ok: true });
});

router.get('/admin/content', requirePermission('content:view'), (_req, res) => {
  const rows = db
    .prepare(
      'SELECT id, course_key, content_type, title, description, data_json, status, updated_by, created_at, updated_at FROM content_library ORDER BY updated_at DESC'
    )
    .all();
  res.json(rows.map((r) => ({ ...r, data: parseJsonSafe(r.data_json, {}) })));
});

router.post('/admin/content', requirePermission('content:edit'), (req, res) => {
  const schema = z.object({
    course_key: z.string().min(2).max(120),
    content_type: z.enum(['course', 'book', 'syllabus', 'pyp', 'mock_test']),
    title: z.string().min(2).max(200),
    description: z.string().max(1000).optional().nullable(),
    data: z.record(z.any()).optional(),
    status: z.enum(['active', 'draft', 'archived']).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid content payload' });
  const now = nowIso();
  const row = db.prepare(
    'INSERT INTO content_library (course_key, content_type, title, description, data_json, status, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(
    parsed.data.course_key,
    parsed.data.content_type,
    parsed.data.title,
    parsed.data.description || null,
    JSON.stringify(parsed.data.data || {}),
    parsed.data.status || 'active',
    req.user.id,
    now,
    now
  );
  db.prepare('INSERT INTO content_versions (content_id, version, snapshot_json, created_by, created_at) VALUES (?, 1, ?, ?, ?)')
    .run(row.lastInsertRowid, JSON.stringify({ ...parsed.data, status: parsed.data.status || 'active' }), req.user.id, now);
  createAuditLog({ actor: req.user, action: 'content_create', targetType: 'content', targetId: row.lastInsertRowid, details: parsed.data });
  res.status(201).json({ ok: true, id: row.lastInsertRowid });
});

router.post('/admin/content/:id', requirePermission('content:edit'), (req, res) => {
  const schema = z.object({
    course_key: z.string().min(2).max(120).optional(),
    title: z.string().min(2).max(200).optional(),
    description: z.string().max(1000).optional().nullable(),
    data: z.record(z.any()).optional(),
    status: z.enum(['active', 'draft', 'archived']).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid content update payload' });
  const existing = db.prepare('SELECT * FROM content_library WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Content item not found' });
  const dataJson = parsed.data.data !== undefined ? JSON.stringify(parsed.data.data || {}) : existing.data_json;
  const next = {
    course_key: parsed.data.course_key || existing.course_key || '',
    title: parsed.data.title || existing.title,
    description: parsed.data.description !== undefined ? parsed.data.description : existing.description,
    data_json: dataJson,
    status: parsed.data.status || existing.status,
  };
  db.prepare(
    'UPDATE content_library SET course_key = ?, title = ?, description = ?, data_json = ?, status = ?, updated_by = ?, updated_at = ? WHERE id = ?'
  ).run(next.course_key, next.title, next.description, next.data_json, next.status, req.user.id, nowIso(), req.params.id);
  const version = db.prepare('SELECT COALESCE(MAX(version), 0) + 1 AS v FROM content_versions WHERE content_id = ?').get(req.params.id).v;
  db.prepare('INSERT INTO content_versions (content_id, version, snapshot_json, created_by, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(req.params.id, version, JSON.stringify(next), req.user.id, nowIso());
  createAuditLog({ actor: req.user, action: 'content_update', targetType: 'content', targetId: req.params.id, details: parsed.data });
  res.json({ ok: true, version });
});

router.get('/admin/content/:id/versions', requirePermission('content:view'), (req, res) => {
  const rows = db.prepare(
    'SELECT id, content_id, version, snapshot_json, created_by, created_at FROM content_versions WHERE content_id = ? ORDER BY version DESC'
  ).all(req.params.id);
  res.json(rows.map((r) => ({ ...r, snapshot: parseJsonSafe(r.snapshot_json, {}) })));
});

router.post('/admin/content/:id/rollback', requirePermission('content:edit'), requireElevatedAccess, (req, res) => {
  const schema = z.object({ version: z.number().int().positive() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'version is required' });
  const v = db.prepare('SELECT snapshot_json FROM content_versions WHERE content_id = ? AND version = ?').get(req.params.id, parsed.data.version);
  if (!v) return res.status(404).json({ error: 'Version not found' });
  const snap = parseJsonSafe(v.snapshot_json, null);
  if (!snap) return res.status(400).json({ error: 'Version payload invalid' });
  const snapshotData = snap.data_json || JSON.stringify(snap.data || {});
  db.prepare(
    'UPDATE content_library SET course_key=?, title=?, description=?, data_json=?, status=?, updated_by=?, updated_at=? WHERE id=?'
  ).run(
    snap.course_key || '',
    snap.title || '',
    snap.description || null,
    snapshotData,
    snap.status || 'draft',
    req.user.id,
    nowIso(),
    req.params.id
  );
  const next = db.prepare('SELECT COALESCE(MAX(version), 0) + 1 AS v FROM content_versions WHERE content_id = ?').get(req.params.id).v;
  db.prepare('INSERT INTO content_versions (content_id, version, snapshot_json, created_by, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(req.params.id, next, JSON.stringify(snap), req.user.id, nowIso());
  createAuditLog({ actor: req.user, action: 'content_rollback', targetType: 'content', targetId: req.params.id, details: { to_version: parsed.data.version } });
  res.json({ ok: true, version: next });
});

router.get('/admin/content/:id/diff', requirePermission('content:view'), (req, res) => {
  const fromVersion = Number(req.query.from || 0);
  const toVersion = Number(req.query.to || 0);
  if (!fromVersion || !toVersion) return res.status(400).json({ error: 'from and to versions are required' });
  const from = db.prepare('SELECT snapshot_json FROM content_versions WHERE content_id = ? AND version = ?').get(req.params.id, fromVersion);
  const to = db.prepare('SELECT snapshot_json FROM content_versions WHERE content_id = ? AND version = ?').get(req.params.id, toVersion);
  if (!from || !to) return res.status(404).json({ error: 'Version not found' });
  const a = parseJsonSafe(from.snapshot_json, {});
  const b = parseJsonSafe(to.snapshot_json, {});
  const keys = Array.from(new Set([...Object.keys(a), ...Object.keys(b)]));
  const diff = keys
    .filter((k) => JSON.stringify(a[k]) !== JSON.stringify(b[k]))
    .map((k) => ({ field: k, from: a[k], to: b[k] }));
  res.json({ content_id: Number(req.params.id), from: fromVersion, to: toVersion, diff });
});

router.get('/admin/roles', requirePermission('audit:view'), (_req, res) => {
  const rows = db.prepare('SELECT role, permissions_json, updated_by, updated_at FROM role_permissions ORDER BY role').all();
  res.json(rows.map((r) => ({ ...r, permissions: parseJsonSafe(r.permissions_json, []) })));
});

router.post('/admin/roles/:role', requirePermission('audit:view'), (req, res) => {
  const schema = z.object({ permissions: z.array(z.string()).min(1) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid permissions payload' });
  db.prepare(
    `INSERT INTO role_permissions (role, permissions_json, updated_by, updated_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(role) DO UPDATE SET permissions_json = excluded.permissions_json, updated_by = excluded.updated_by, updated_at = excluded.updated_at`
  ).run(req.params.role, JSON.stringify(parsed.data.permissions), req.user.id, nowIso());
  createAuditLog({ actor: req.user, action: 'role_permissions_update', targetType: 'role', targetId: req.params.role, details: parsed.data });
  res.json({ ok: true });
});

router.get('/admin/audit', requirePermission('audit:view'), (req, res) => {
  const format = String(req.query.format || 'json');
  const rows = db.prepare(
    'SELECT id, actor_user_id, actor_email, action, target_type, target_id, details_json, created_at, prev_hash, hash, signature FROM audit_log ORDER BY id DESC LIMIT 1000'
  ).all();
  const parsed = rows.map((r) => ({ ...r, details: parseJsonSafe(r.details_json, {}) }));
  if (format === 'csv') {
    const header = 'id,actor_user_id,actor_email,action,target_type,target_id,created_at,hash\n';
    const body = parsed
      .map((r) => {
        const cells = [r.id, r.actor_user_id || '', r.actor_email || '', r.action, r.target_type, r.target_id || '', r.created_at, r.hash];
        return cells.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(',');
      })
      .join('\n');
    res.setHeader('content-type', 'text/csv');
    return res.send(`${header}${body}\n`);
  }
  return res.json(parsed);
});

router.get('/admin/ai/guardrails', requirePermission('ai:manage'), (_req, res) => {
  const row = db.prepare('SELECT * FROM ai_guardrails WHERE id = 1').get();
  res.json(row);
});

router.post('/admin/ai/guardrails', requirePermission('ai:manage'), (req, res) => {
  const schema = z.object({
    pii_redaction: z.boolean(),
    moderation_threshold: z.number().min(0).max(1),
    fallback_behavior: z.string().min(2),
    daily_quota: z.number().int().positive(),
    per_user_quota: z.number().int().positive(),
    per_feature_quota: z.number().int().positive(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid guardrails payload' });
  db.prepare(
    `UPDATE ai_guardrails SET pii_redaction=?, moderation_threshold=?, fallback_behavior=?, daily_quota=?,
     per_user_quota=?, per_feature_quota=?, updated_by=?, updated_at=? WHERE id=1`
  ).run(
    parsed.data.pii_redaction ? 1 : 0,
    parsed.data.moderation_threshold,
    parsed.data.fallback_behavior,
    parsed.data.daily_quota,
    parsed.data.per_user_quota,
    parsed.data.per_feature_quota,
    req.user.id,
    nowIso()
  );
  createAuditLog({ actor: req.user, action: 'ai_guardrails_update', targetType: 'ai', targetId: 'guardrails', details: parsed.data });
  res.json({ ok: true });
});

router.get('/admin/ai/prompts', requirePermission('ai:manage'), (_req, res) => {
  const rows = db.prepare('SELECT id, feature, version, template, status, created_by, created_at FROM ai_prompt_templates ORDER BY feature, version DESC').all();
  res.json(rows);
});

router.post('/admin/ai/prompts', requirePermission('ai:manage'), (req, res) => {
  const schema = z.object({ feature: z.string().min(2), template: z.string().min(5), status: z.enum(['active', 'draft', 'archived']).optional() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid prompt payload' });
  const next = db.prepare('SELECT COALESCE(MAX(version), 0) + 1 AS v FROM ai_prompt_templates WHERE feature = ?').get(parsed.data.feature).v;
  const row = db.prepare(
    'INSERT INTO ai_prompt_templates (feature, version, template, status, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(parsed.data.feature, next, parsed.data.template, parsed.data.status || 'active', req.user.id, nowIso());
  createAuditLog({ actor: req.user, action: 'ai_prompt_create', targetType: 'ai_prompt', targetId: row.lastInsertRowid, details: parsed.data });
  res.status(201).json({ ok: true, id: row.lastInsertRowid, version: next });
});

router.get('/admin/ai/routes', requirePermission('ai:manage'), (_req, res) => {
  const rows = db.prepare('SELECT id, feature, model, fallback_model, updated_by, updated_at FROM ai_model_routes ORDER BY feature').all();
  res.json(rows);
});

router.post('/admin/ai/routes', requirePermission('ai:manage'), (req, res) => {
  const schema = z.object({ feature: z.string().min(2), model: z.string().min(2), fallback_model: z.string().optional().nullable() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid route payload' });
  db.prepare(
    `INSERT INTO ai_model_routes (feature, model, fallback_model, updated_by, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(feature) DO UPDATE SET model = excluded.model, fallback_model = excluded.fallback_model, updated_by = excluded.updated_by, updated_at = excluded.updated_at`
  ).run(parsed.data.feature, parsed.data.model, parsed.data.fallback_model || null, req.user.id, nowIso());
  createAuditLog({ actor: req.user, action: 'ai_route_update', targetType: 'ai_route', targetId: parsed.data.feature, details: parsed.data });
  res.json({ ok: true });
});

router.post('/ai/feedback', (req, res) => {
  const schema = z.object({
    feature: z.string().min(2),
    output_text: z.string().min(2),
    rating: z.number().int().min(1).max(5),
    note: z.string().max(1000).optional().nullable(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid feedback payload' });
  const row = db.prepare(
    'INSERT INTO ai_feedback_queue (user_id, feature, output_text, rating, note, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(req.user.id, parsed.data.feature, parsed.data.output_text, parsed.data.rating, parsed.data.note || null, 'open', nowIso());
  res.status(201).json({ ok: true, id: row.lastInsertRowid });
});

router.get('/admin/ai/feedback-queue', requirePermission('ai:manage'), (_req, res) => {
  const rows = db.prepare('SELECT * FROM ai_feedback_queue ORDER BY created_at DESC').all();
  res.json(rows);
});

router.post('/admin/api/keys', requirePermission('api:manage'), (req, res) => {
  const schema = z.object({
    name: z.string().min(2),
    rate_limit_per_min: z.number().int().positive().optional(),
    quota_per_day: z.number().int().positive().optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid api key payload' });
  const key = createApiKey();
  const row = db.prepare(
    'INSERT INTO api_keys (name, key_prefix, key_hash, status, rate_limit_per_min, quota_per_day, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(
    parsed.data.name,
    key.keyPrefix,
    key.keyHash,
    'active',
    parsed.data.rate_limit_per_min || 60,
    parsed.data.quota_per_day || 5000,
    req.user.id,
    nowIso()
  );
  createAuditLog({ actor: req.user, action: 'api_key_create', targetType: 'api_key', targetId: row.lastInsertRowid, details: { name: parsed.data.name } });
  res.status(201).json({ ok: true, id: row.lastInsertRowid, api_key: key.raw, key_prefix: key.keyPrefix });
});

router.get('/admin/api/keys', requirePermission('api:manage'), (_req, res) => {
  const rows = db.prepare(
    'SELECT id, name, key_prefix, status, rate_limit_per_min, quota_per_day, last_used_at, created_by, created_at FROM api_keys ORDER BY created_at DESC'
  ).all();
  res.json(rows);
});

router.post('/admin/api/keys/:id/revoke', requirePermission('api:manage'), (req, res) => {
  const r = db.prepare("UPDATE api_keys SET status = 'revoked' WHERE id = ?").run(req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'API key not found' });
  createAuditLog({ actor: req.user, action: 'api_key_revoke', targetType: 'api_key', targetId: req.params.id, details: {} });
  res.json({ ok: true });
});

router.post('/admin/api/keys/:id/rotate', requirePermission('api:manage'), (req, res) => {
  const key = createApiKey();
  const r = db.prepare('UPDATE api_keys SET key_prefix = ?, key_hash = ?, status = ?, last_used_at = NULL WHERE id = ?')
    .run(key.keyPrefix, key.keyHash, 'active', req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'API key not found' });
  createAuditLog({ actor: req.user, action: 'api_key_rotate', targetType: 'api_key', targetId: req.params.id, details: {} });
  res.json({ ok: true, api_key: key.raw, key_prefix: key.keyPrefix });
});

router.post('/admin/api/rules', requirePermission('api:manage'), (req, res) => {
  const schema = z.object({ endpoint: z.string().min(2), rate_limit_per_min: z.number().int().positive(), quota_per_day: z.number().int().positive() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid payload' });
  db.prepare(
    `INSERT INTO config_settings (config_key, config_value, validation_rule, updated_by, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(config_key) DO UPDATE SET config_value = excluded.config_value, validation_rule = excluded.validation_rule, updated_by = excluded.updated_by, updated_at = excluded.updated_at`
  ).run(
    `api_rule:${parsed.data.endpoint}`,
    JSON.stringify({ rate_limit_per_min: parsed.data.rate_limit_per_min, quota_per_day: parsed.data.quota_per_day }),
    'json',
    req.user.id,
    nowIso()
  );
  createAuditLog({ actor: req.user, action: 'api_rule_update', targetType: 'api_rule', targetId: parsed.data.endpoint, details: parsed.data });
  res.json({ ok: true });
});

router.get('/admin/api/errors', requirePermission('api:manage'), (_req, res) => {
  const rows = db.prepare(
    `SELECT endpoint,
      SUM(CASE WHEN status_code BETWEEN 400 AND 499 THEN 1 ELSE 0 END) AS e4,
      SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END) AS e5,
      COUNT(*) AS total
      FROM api_request_logs
      GROUP BY endpoint
      ORDER BY total DESC`
  ).all();
  res.json(rows);
});

router.get('/admin/api/requests', requirePermission('api:manage'), (req, res) => {
  const endpoint = String(req.query.endpoint || '').trim();
  const statusCode = Number(req.query.status_code || 0);
  const rows = db.prepare(
    'SELECT id, user_id, method, endpoint, status_code, latency_ms, source, created_at FROM api_request_logs ORDER BY created_at DESC LIMIT 1000'
  ).all()
    .filter((r) => (endpoint ? r.endpoint === endpoint : true))
    .filter((r) => (statusCode ? Number(r.status_code) === statusCode : true));
  res.json(rows);
});

router.get('/admin/webhooks/failed', requirePermission('api:manage'), (_req, res) => {
  const rows = db.prepare("SELECT * FROM webhook_events WHERE status = 'failed' ORDER BY updated_at DESC").all();
  res.json(rows);
});

router.get('/admin/webhooks/events', requirePermission('api:manage'), (_req, res) => {
  const rows = db.prepare(
    `SELECT e.id, e.provider, e.event_id, e.event_name, e.status, e.retry_count, e.last_error, e.signature_valid, e.created_at, e.updated_at,
      (SELECT COUNT(*) FROM webhook_event_transitions t WHERE t.webhook_event_id = e.id) AS transitions_count
      FROM webhook_events e
      ORDER BY e.updated_at DESC LIMIT 200`
  ).all();
  res.json(rows);
});

router.get('/admin/webhooks/:id/transitions', requirePermission('api:manage'), (req, res) => {
  const rows = db.prepare(
    'SELECT id, webhook_event_id, from_status, to_status, reason, changed_by, changed_at FROM webhook_event_transitions WHERE webhook_event_id = ? ORDER BY changed_at DESC'
  ).all(req.params.id);
  res.json(rows);
});

router.post('/admin/webhooks/:id/replay', requirePermission('payments:webhooks:retry'), (req, res) => {
  const row = db.prepare('SELECT * FROM webhook_events WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Webhook event not found' });
  if (!['failed', 'signature-invalid'].includes(String(row.status || ''))) {
    return res.status(400).json({ error: 'Only failed/signature-invalid webhook events can be retried' });
  }
  appendWebhookTransition({
    webhookEventId: row.id,
    fromStatus: row.status,
    toStatus: 'replayed',
    reason: 'manual_retry',
    changedBy: req.user.id,
  });
  db.prepare("UPDATE webhook_events SET status='replayed', retry_count=retry_count + 1, last_error = NULL, updated_at = ? WHERE id = ?")
    .run(nowIso(), req.params.id);
  createAuditLog({ actor: req.user, action: 'webhook_replay', targetType: 'webhook_event', targetId: req.params.id, details: {} });
  res.json({ ok: true });
});

router.get('/admin/feature-flags', requirePermission('ops:manage'), (_req, res) => {
  const rows = db.prepare('SELECT id, flag_key, description, enabled, scope, scope_value, updated_by, updated_at FROM feature_flags ORDER BY flag_key').all();
  res.json(rows);
});

router.post('/admin/feature-flags', requirePermission('ops:manage'), (req, res) => {
  const schema = z.object({
    flag_key: z.string().min(2),
    description: z.string().max(500).optional().nullable(),
    enabled: z.boolean(),
    scope: z.enum(['global', 'cohort', 'user']),
    scope_value: z.string().optional().nullable(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid feature flag payload' });
  db.prepare(
    `INSERT INTO feature_flags (flag_key, description, enabled, scope, scope_value, updated_by, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(flag_key) DO UPDATE SET description = excluded.description, enabled = excluded.enabled, scope = excluded.scope, scope_value = excluded.scope_value, updated_by = excluded.updated_by, updated_at = excluded.updated_at`
  ).run(parsed.data.flag_key, parsed.data.description || null, parsed.data.enabled ? 1 : 0, parsed.data.scope, parsed.data.scope_value || null, req.user.id, nowIso());
  createAuditLog({ actor: req.user, action: 'feature_flag_update', targetType: 'feature_flag', targetId: parsed.data.flag_key, details: parsed.data });
  res.json({ ok: true });
});

router.get('/admin/config', requirePermission('ops:manage'), (_req, res) => {
  const rows = db.prepare('SELECT id, config_key, config_value, validation_rule, updated_by, updated_at FROM config_settings ORDER BY config_key').all();
  res.json(rows.map((r) => {
    if (r.config_key === PAYMENT_CONFIG_KEY) {
      return {
        ...r,
        config_value: JSON.stringify(maskedPaymentSettings(r.config_value)),
        parsed: maskedPaymentSettings(r.config_value),
      };
    }
    return { ...r, parsed: parseJsonSafe(r.config_value, r.config_value) };
  }));
});

router.get('/admin/config/history', requirePermission('ops:manage'), (_req, res) => {
  const rows = db.prepare('SELECT id, config_key, old_value, new_value, changed_by, created_at FROM config_history ORDER BY created_at DESC LIMIT 1000').all();
  res.json(rows);
});

router.post('/admin/config', requirePermission('ops:manage'), (req, res) => {
  const schema = z.object({
    config_key: z.string().min(2),
    config_value: z.any(),
    validation_rule: z.enum(['json', 'number', 'string', 'boolean']).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid config payload' });
  const existing = db.prepare('SELECT config_value FROM config_settings WHERE config_key = ?').get(parsed.data.config_key);
  if (parsed.data.config_key === PAYMENT_CONFIG_KEY) {
    const paymentParsed = paymentSettingsSchema().safeParse(parsed.data.config_value || {});
    if (!paymentParsed.success) return res.status(400).json({ error: 'payments.gateway requires valid payment settings object' });
    const encrypted = JSON.stringify(encryptPaymentSecrets(paymentParsed.data));
    const now = nowIso();
    db.prepare(
      `INSERT INTO config_settings (config_key, config_value, validation_rule, updated_by, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(config_key) DO UPDATE SET config_value = excluded.config_value, validation_rule = excluded.validation_rule, updated_by = excluded.updated_by, updated_at = excluded.updated_at`
    ).run(PAYMENT_CONFIG_KEY, encrypted, 'json', req.user.id, now);
    db.prepare('INSERT INTO config_history (config_key, old_value, new_value, changed_by, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(PAYMENT_CONFIG_KEY, existing?.config_value || null, encrypted, req.user.id, now);
    createAuditLog({
      actor: req.user,
      action: 'payment_gateway_update',
      targetType: 'payment_gateway',
      targetId: PAYMENT_CONFIG_KEY,
      details: {
        before: existing?.config_value ? maskedPaymentSettings(existing.config_value) : null,
        after: maskedPaymentSettings(encrypted),
      },
    });
    return res.json({ ok: true });
  }
  const val = typeof parsed.data.config_value === 'string' ? parsed.data.config_value : JSON.stringify(parsed.data.config_value);
  const rule = parsed.data.validation_rule || 'json';
  if (rule === 'number' && Number.isNaN(Number(val))) return res.status(400).json({ error: 'config_value must be number' });
  if (rule === 'boolean' && !['true', 'false'].includes(String(val))) return res.status(400).json({ error: 'config_value must be boolean' });
  if (rule === 'json') {
    try {
      JSON.parse(val);
    } catch (_e) {
      return res.status(400).json({ error: 'config_value must be valid JSON string/object' });
    }
  }
  db.prepare(
    `INSERT INTO config_settings (config_key, config_value, validation_rule, updated_by, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(config_key) DO UPDATE SET config_value = excluded.config_value, validation_rule = excluded.validation_rule, updated_by = excluded.updated_by, updated_at = excluded.updated_at`
  ).run(parsed.data.config_key, val, rule, req.user.id, nowIso());
  db.prepare('INSERT INTO config_history (config_key, old_value, new_value, changed_by, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(parsed.data.config_key, existing?.config_value || null, val, req.user.id, nowIso());
  createAuditLog({ actor: req.user, action: 'config_update', targetType: 'config', targetId: parsed.data.config_key, details: { rule } });
  res.json({ ok: true });
});

router.get('/admin/payments/settings', requirePermission('payments:settings'), (_req, res) => {
  const row = db.prepare('SELECT config_value, updated_by, updated_at FROM config_settings WHERE config_key = ?').get(PAYMENT_CONFIG_KEY);
  if (!row) return res.json({ exists: false, settings: null });
  return res.json({
    exists: true,
    updated_by: row.updated_by || null,
    updated_at: row.updated_at || null,
    settings: maskedPaymentSettings(row.config_value),
  });
});

router.post('/admin/payments/settings', requirePermission('payments:settings'), (req, res) => {
  const parsedManaged = externalPaymentSettingsSchema().safeParse(req.body || {});
  const parsed = parsedManaged.success ? parsedManaged : paymentSettingsSchema().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid payment settings payload' });
  const oldRow = db.prepare('SELECT config_value FROM config_settings WHERE config_key = ?').get(PAYMENT_CONFIG_KEY);
  const safe = parsed.data;
  const encrypted = encryptPaymentSecrets(parsedManaged.success ? {
    provider: safe.provider,
    mode: safe.mode,
    currency: safe.currency,
    managed_externally: true,
    external_secret_ref: safe.external_secret_ref,
  } : {
    provider: safe.provider,
    mode: safe.mode,
    currency: safe.currency,
    key_id: safe.key_id,
    key_secret: safe.key_secret,
    webhook_secret: safe.webhook_secret || null,
  });
  const nextVal = JSON.stringify(encrypted);
  const now = nowIso();
  db.prepare(
    `INSERT INTO config_settings (config_key, config_value, validation_rule, updated_by, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(config_key) DO UPDATE SET config_value = excluded.config_value, validation_rule = excluded.validation_rule, updated_by = excluded.updated_by, updated_at = excluded.updated_at`
  ).run(PAYMENT_CONFIG_KEY, nextVal, 'json', req.user.id, now);
  db.prepare('INSERT INTO config_history (config_key, old_value, new_value, changed_by, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(PAYMENT_CONFIG_KEY, oldRow?.config_value || null, nextVal, req.user.id, now);
  const oldMasked = oldRow?.config_value ? maskedPaymentSettings(oldRow.config_value) : null;
  const newMasked = maskedPaymentSettings(nextVal);
  createAuditLog({
    actor: req.user,
    action: 'payment_gateway_update',
    targetType: 'payment_gateway',
    targetId: PAYMENT_CONFIG_KEY,
    details: { before: oldMasked, after: newMasked },
  });
  const latest = db.prepare('SELECT MAX(version_no) AS v FROM payment_secret_versions').get();
  const nextVersion = Number(latest?.v || 0) + 1;
  db.prepare("UPDATE payment_secret_versions SET status = 'superseded' WHERE status = 'active'").run();
  db.prepare(
    'INSERT INTO payment_secret_versions (version_no, secret_ref, encrypted_payload, status, reason, changed_by, created_at, rolled_back_from_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(
    nextVersion,
    parsedManaged.success ? safe.external_secret_ref : null,
    nextVal,
    'active',
    parsedManaged.success ? 'external_secret_ref_update' : 'direct_secret_update',
    req.user.id,
    now,
    null
  );
  return res.json({ ok: true, settings: newMasked });
});

router.post('/admin/payments/test-connection', requirePermission('payments:test'), async (req, res) => {
  const rl = assertConnectionRateLimit(req.user.id);
  if (!rl.ok) return res.status(429).json({ ok: false, diagnostics: [{ code: 'RATE_LIMITED', message: rl.error }] });
  const source = String(req.body?.source || 'saved').trim();
  let cfg;
  if (source === 'saved') {
    const row = db.prepare('SELECT config_value FROM config_settings WHERE config_key = ?').get(PAYMENT_CONFIG_KEY);
    if (!row) return res.status(404).json({ ok: false, provider: null, mode: null, diagnostics: [{ code: 'NOT_CONFIGURED', message: 'Saved payment settings not found' }] });
    cfg = hydratePaymentSecrets(decryptPaymentSecrets(row.config_value));
  } else {
    const parsedManaged = externalPaymentSettingsSchema().safeParse(req.body?.settings || req.body || {});
    const parsed = parsedManaged.success ? parsedManaged : paymentSettingsSchema().safeParse(req.body?.settings || req.body || {});
    if (!parsed.success) return res.status(400).json({ ok: false, provider: null, mode: null, diagnostics: [{ code: 'INVALID_PAYLOAD', message: 'Payload failed payment validation' }] });
    cfg = hydratePaymentSecrets(parsedManaged.success ? {
      provider: parsed.data.provider,
      mode: parsed.data.mode,
      currency: parsed.data.currency,
      managed_externally: true,
      external_secret_ref: parsed.data.external_secret_ref,
    } : parsed.data);
  }
  if (isCircuitOpen(cfg.provider, cfg.mode)) {
    return res.status(429).json({
      ok: false,
      provider: cfg.provider || null,
      mode: cfg.mode || null,
      diagnostics: [{ code: 'CIRCUIT_OPEN', message: 'Connection tests temporarily paused due to repeated provider failures' }],
    });
  }
  const diagnostics = [];
  const details = { provider: cfg.provider || null, mode: cfg.mode || null, endpoint: null, status_code: null };
  try {
    if (cfg.provider === 'razorpay') {
      details.endpoint = 'https://api.razorpay.com/v1/payments?count=1';
      const auth = Buffer.from(`${cfg.key_id}:${cfg.key_secret}`).toString('base64');
      const out = await requestJson({ hostname: 'api.razorpay.com', path: '/v1/payments?count=1', method: 'GET', headers: { Authorization: `Basic ${auth}` } });
      details.status_code = out.statusCode;
      if (out.statusCode >= 200 && out.statusCode < 300) diagnostics.push({ code: 'AUTH_OK', message: 'Razorpay credentials validated' });
      else diagnostics.push({ code: 'AUTH_FAILED', message: `Razorpay returned status ${out.statusCode}` });
    } else if (cfg.provider === 'stripe') {
      details.endpoint = 'https://api.stripe.com/v1/charges?limit=1';
      const auth = Buffer.from(`${cfg.key_secret}:`).toString('base64');
      const out = await requestJson({ hostname: 'api.stripe.com', path: '/v1/charges?limit=1', method: 'GET', headers: { Authorization: `Basic ${auth}` } });
      details.status_code = out.statusCode;
      if (out.statusCode >= 200 && out.statusCode < 300) diagnostics.push({ code: 'AUTH_OK', message: 'Stripe credentials validated' });
      else diagnostics.push({ code: 'AUTH_FAILED', message: `Stripe returned status ${out.statusCode}` });
    } else {
      const cashfreeHost = cfg.mode === 'live' ? 'api.cashfree.com' : 'sandbox.cashfree.com';
      details.endpoint = `https://${cashfreeHost}/pg/orders`;
      const out = await requestJson({
        hostname: cashfreeHost,
        path: '/pg/orders?limit=1',
        method: 'GET',
        headers: {
          'x-client-id': String(cfg.key_id || ''),
          'x-client-secret': String(cfg.key_secret || ''),
          'x-api-version': '2022-09-01',
        },
      });
      details.status_code = out.statusCode;
      if (out.statusCode >= 200 && out.statusCode < 300) diagnostics.push({ code: 'AUTH_OK', message: 'Cashfree credentials validated' });
      else diagnostics.push({ code: 'AUTH_FAILED', message: `Cashfree returned status ${out.statusCode}` });
    }
  } catch (err) {
    diagnostics.push({ code: 'NETWORK_ERROR', message: err.message || 'Failed to connect to provider' });
  }
  const ok = diagnostics.some((d) => d.code === 'AUTH_OK');
  updateCircuitState(cfg.provider, cfg.mode, ok);
  createAuditLog({
    actor: req.user,
    action: 'payment_gateway_test_connection',
    targetType: 'payment_gateway',
    targetId: PAYMENT_CONFIG_KEY,
    details: { provider: details.provider, mode: details.mode, ok, diagnostics },
  });
  return res.json({ ok, provider: details.provider, mode: details.mode, diagnostics, details });
});

router.get('/admin/payments/versions', requirePermission('payments:settings'), (_req, res) => {
  const rows = db.prepare(
    'SELECT id, version_no, secret_ref, status, reason, changed_by, created_at, rolled_back_from_version FROM payment_secret_versions ORDER BY version_no DESC LIMIT 100'
  ).all();
  res.json(rows);
});

router.post('/admin/payments/rotate', requirePermission('payments:settings'), (req, res) => {
  const schema = z.object({
    provider: z.enum(['razorpay', 'stripe', 'cashfree']),
    mode: z.enum(['test', 'live']),
    currency: z.enum(PAYMENT_CURRENCIES),
    key_id: z.string().min(6).max(150).optional(),
    key_secret: z.string().min(8).max(200).optional(),
    webhook_secret: z.string().max(200).optional().nullable(),
    external_secret_ref: z.string().min(3).max(120).optional(),
    reason: z.string().min(5).max(200).optional(),
  });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ error: 'Invalid rotate payload' });
  const useExternal = Boolean(parsed.data.external_secret_ref);
  const payload = useExternal
    ? encryptPaymentSecrets({
      provider: parsed.data.provider,
      mode: parsed.data.mode,
      currency: parsed.data.currency,
      managed_externally: true,
      external_secret_ref: parsed.data.external_secret_ref,
    })
    : encryptPaymentSecrets({
      provider: parsed.data.provider,
      mode: parsed.data.mode,
      currency: parsed.data.currency,
      key_id: parsed.data.key_id || '',
      key_secret: parsed.data.key_secret || '',
      webhook_secret: parsed.data.webhook_secret || null,
    });
  const nextVal = JSON.stringify(payload);
  const now = nowIso();
  const latest = db.prepare('SELECT MAX(version_no) AS v FROM payment_secret_versions').get();
  const nextVersion = Number(latest?.v || 0) + 1;
  db.prepare("UPDATE payment_secret_versions SET status = 'superseded' WHERE status = 'active'").run();
  db.prepare(
    'INSERT INTO payment_secret_versions (version_no, secret_ref, encrypted_payload, status, reason, changed_by, created_at, rolled_back_from_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(nextVersion, parsed.data.external_secret_ref || null, nextVal, 'active', parsed.data.reason || 'rotation', req.user.id, now, null);
  db.prepare(
    `INSERT INTO config_settings (config_key, config_value, validation_rule, updated_by, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(config_key) DO UPDATE SET config_value = excluded.config_value, validation_rule = excluded.validation_rule, updated_by = excluded.updated_by, updated_at = excluded.updated_at`
  ).run(PAYMENT_CONFIG_KEY, nextVal, 'json', req.user.id, now);
  db.prepare('INSERT INTO config_history (config_key, old_value, new_value, changed_by, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(PAYMENT_CONFIG_KEY, null, nextVal, req.user.id, now);
  createAuditLog({ actor: req.user, action: 'payment_gateway_rotate', targetType: 'payment_gateway', targetId: PAYMENT_CONFIG_KEY, details: { version: nextVersion, external: useExternal } });
  return res.status(201).json({ ok: true, version: nextVersion, settings: maskedPaymentSettings(nextVal) });
});

router.post('/admin/payments/rollback', requirePermission('payments:settings'), (req, res) => {
  const schema = z.object({ version_no: z.number().int().positive(), reason: z.string().min(5).max(200).optional() });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ error: 'Invalid rollback payload' });
  const version = db.prepare('SELECT version_no, secret_ref, encrypted_payload FROM payment_secret_versions WHERE version_no = ?').get(parsed.data.version_no);
  if (!version) return res.status(404).json({ error: 'Version not found' });
  const now = nowIso();
  const latest = db.prepare('SELECT MAX(version_no) AS v FROM payment_secret_versions').get();
  const nextVersion = Number(latest?.v || 0) + 1;
  db.prepare("UPDATE payment_secret_versions SET status = 'superseded' WHERE status = 'active'").run();
  db.prepare(
    'INSERT INTO payment_secret_versions (version_no, secret_ref, encrypted_payload, status, reason, changed_by, created_at, rolled_back_from_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(nextVersion, version.secret_ref || null, version.encrypted_payload, 'active', parsed.data.reason || 'rollback', req.user.id, now, version.version_no);
  db.prepare(
    `INSERT INTO config_settings (config_key, config_value, validation_rule, updated_by, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(config_key) DO UPDATE SET config_value = excluded.config_value, validation_rule = excluded.validation_rule, updated_by = excluded.updated_by, updated_at = excluded.updated_at`
  ).run(PAYMENT_CONFIG_KEY, version.encrypted_payload, 'json', req.user.id, now);
  createAuditLog({ actor: req.user, action: 'payment_gateway_rollback', targetType: 'payment_gateway', targetId: PAYMENT_CONFIG_KEY, details: { rolled_back_to: version.version_no, new_version: nextVersion } });
  return res.json({ ok: true, version: nextVersion, rolled_back_to: version.version_no, settings: maskedPaymentSettings(version.encrypted_payload) });
});

router.post('/admin/payments/webhooks/validate', requirePermission('payments:webhooks:validate'), (req, res) => {
  const schema = z.object({
    provider: z.enum(['razorpay', 'stripe', 'cashfree']),
    event_id: z.string().min(3).max(120),
    event_name: z.string().min(2).max(160),
    signature: z.string().min(6),
    payload: z.any(),
    timestamp: z.number().int().positive().optional(),
  });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ error: 'Invalid webhook validation payload' });
  const p = parsed.data;
  const payloadText = typeof p.payload === 'string' ? p.payload : JSON.stringify(p.payload || {});

  const existing = db.prepare('SELECT id, seen_count FROM webhook_replay_guard WHERE provider = ? AND event_id = ?').get(p.provider, p.event_id);
  if (existing) {
    db.prepare('UPDATE webhook_replay_guard SET seen_count = seen_count + 1, last_seen_at = ? WHERE id = ?').run(nowIso(), existing.id);
    return res.status(409).json({ ok: false, status: 'replay-detected', diagnostics: [{ code: 'REPLAY_DETECTED', message: 'Duplicate webhook event id detected' }] });
  }

  const cfgRow = db.prepare('SELECT config_value FROM config_settings WHERE config_key = ?').get(PAYMENT_CONFIG_KEY);
  if (!cfgRow) return res.status(404).json({ ok: false, status: 'missing-config', diagnostics: [{ code: 'NOT_CONFIGURED', message: 'Payment gateway configuration missing' }] });
  const cfg = hydratePaymentSecrets(decryptPaymentSecrets(cfgRow.config_value));
  const secret = String(cfg.webhook_secret || '');
  if (!secret) return res.status(400).json({ ok: false, status: 'missing-secret', diagnostics: [{ code: 'MISSING_WEBHOOK_SECRET', message: 'Webhook secret is not configured' }] });

  let expected = '';
  if (p.provider === 'razorpay' || p.provider === 'cashfree') {
    expected = crypto.createHmac('sha256', secret).update(payloadText).digest('hex');
  } else {
    const ts = Number(p.timestamp || 0);
    if (!ts) return res.status(400).json({ ok: false, status: 'invalid-payload', diagnostics: [{ code: 'MISSING_TIMESTAMP', message: 'Stripe webhook validation requires timestamp' }] });
    if (Math.abs(Date.now() - (ts * 1000)) > WEBHOOK_TIMESTAMP_TOLERANCE_MS) {
      return res.status(400).json({ ok: false, status: 'invalid-timestamp', diagnostics: [{ code: 'TIMESTAMP_OUT_OF_WINDOW', message: 'Webhook timestamp outside replay window' }] });
    }
    expected = crypto.createHmac('sha256', secret).update(`${ts}.${payloadText}`).digest('hex');
  }

  const valid = safeTimingEqual(normalizeSig(expected), normalizeSig(p.signature));
  const now = nowIso();
  db.prepare('INSERT INTO webhook_replay_guard (provider, event_id, first_seen_at, last_seen_at, seen_count) VALUES (?, ?, ?, ?, ?)')
    .run(p.provider, p.event_id, now, now, 1);
  const initialStatus = valid ? 'delivered' : 'signature-invalid';
  const row = db.prepare(
    'INSERT INTO webhook_events (provider, event_id, event_name, payload_json, status, retry_count, last_error, signature_valid, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)'
  ).run(p.provider, p.event_id, p.event_name, payloadText, initialStatus, valid ? null : 'Signature validation failed', valid ? 1 : 0, now, now);
  appendWebhookTransition({
    webhookEventId: row.lastInsertRowid,
    fromStatus: null,
    toStatus: initialStatus,
    reason: valid ? 'validated' : 'signature-mismatch',
    changedBy: req.user.id,
  });
  createAuditLog({
    actor: req.user,
    action: 'webhook_signature_validate',
    targetType: 'webhook_event',
    targetId: row.lastInsertRowid,
    details: { provider: p.provider, event_id: p.event_id, status: initialStatus },
  });
  return res.status(valid ? 200 : 400).json({ ok: valid, event_id: p.event_id, status: initialStatus, diagnostics: [{ code: valid ? 'SIGNATURE_VALID' : 'SIGNATURE_INVALID', message: valid ? 'Webhook signature validated' : 'Webhook signature invalid' }] });
});

router.get('/admin/backup/list', requirePermission('ops:manage'), (_req, res) => {
  const rows = db.prepare('SELECT * FROM backup_jobs ORDER BY created_at DESC LIMIT 100').all();
  res.json(rows);
});

router.post('/admin/backup/create', requirePermission('ops:manage'), requireElevatedAccess, (req, res) => {
  const backupDir = path.join(path.dirname(db.__path), 'backups');
  if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });
  const filename = `app-${Date.now()}.db`;
  const backupPath = path.join(backupDir, filename);
  try {
    if (!isSafeBackupPath(backupPath)) return res.status(400).json({ error: 'Unsafe backup path generated' });
    const safeBackupPath = backupPath.replace(/'/g, "''");
    db.exec(`VACUUM INTO '${safeBackupPath}'`);
    const row = db.prepare('INSERT INTO backup_jobs (backup_type, backup_path, status, triggered_by, created_at) VALUES (?, ?, ?, ?, ?)')
      .run('manual', backupPath, 'completed', req.user.id, nowIso());
    createAuditLog({ actor: req.user, action: 'backup_create', targetType: 'backup', targetId: row.lastInsertRowid, details: { backupPath } });
    res.status(201).json({ ok: true, id: row.lastInsertRowid, backup_path: backupPath });
  } catch (_err) {
    res.status(500).json({ error: 'Backup creation failed' });
  }
});

router.post('/admin/backup/restore', requirePermission('ops:manage'), requireElevatedAccess, requireDualApproval('restore_backup'), (req, res) => {
  const schema = z.object({ backup_path: z.string().min(3) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'backup_path is required' });
  if (!fs.existsSync(parsed.data.backup_path)) return res.status(404).json({ error: 'Backup file not found' });
  const row = db.prepare(
    'INSERT INTO backup_jobs (backup_type, backup_path, status, triggered_by, created_at) VALUES (?, ?, ?, ?, ?)'
  ).run('restore_request', parsed.data.backup_path, 'pending_restart', req.user.id, nowIso());
  createAuditLog({
    actor: req.user,
    action: 'backup_restore_requested',
    targetType: 'backup',
    targetId: row.lastInsertRowid,
    details: { backup_path: parsed.data.backup_path },
  });
  res.status(202).json({
    ok: true,
    message: 'Restore request recorded. Apply backup during controlled restart to avoid live database corruption.',
    restore_job_id: row.lastInsertRowid,
  });
});

router.get('/admin/retention-policies', requirePermission('ops:manage'), (_req, res) => {
  const rows = db.prepare('SELECT * FROM retention_policies ORDER BY policy_key').all();
  res.json(rows);
});

router.post('/admin/retention-policies', requirePermission('ops:manage'), (req, res) => {
  const schema = z.object({ policy_key: z.string().min(2), keep_days: z.number().int().positive(), enabled: z.boolean() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid payload' });
  db.prepare(
    `INSERT INTO retention_policies (policy_key, keep_days, enabled, updated_by, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(policy_key) DO UPDATE SET keep_days=excluded.keep_days, enabled=excluded.enabled, updated_by=excluded.updated_by, updated_at=excluded.updated_at`
  ).run(parsed.data.policy_key, parsed.data.keep_days, parsed.data.enabled ? 1 : 0, req.user.id, nowIso());
  createAuditLog({ actor: req.user, action: 'retention_policy_update', targetType: 'retention', targetId: parsed.data.policy_key, details: parsed.data });
  res.json({ ok: true });
});

router.get('/admin/release-controls', requirePermission('ops:manage'), (_req, res) => {
  const rows = db.prepare('SELECT * FROM release_controls ORDER BY control_key').all();
  res.json(rows);
});

router.post('/admin/release-controls', requirePermission('ops:manage'), (req, res) => {
  const schema = z.object({ control_key: z.string().min(2), enabled: z.boolean(), reason: z.string().optional().nullable() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid payload' });
  db.prepare(
    `INSERT INTO release_controls (control_key, enabled, reason, updated_by, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(control_key) DO UPDATE SET enabled=excluded.enabled, reason=excluded.reason, updated_by=excluded.updated_by, updated_at=excluded.updated_at`
  ).run(parsed.data.control_key, parsed.data.enabled ? 1 : 0, parsed.data.reason || null, req.user.id, nowIso());
  createAuditLog({ actor: req.user, action: 'release_control_update', targetType: 'release', targetId: parsed.data.control_key, details: parsed.data });
  res.json({ ok: true });
});

router.get('/admin/jobs', requirePermission('ops:manage'), (_req, res) => {
  const rows = db.prepare('SELECT * FROM background_jobs ORDER BY updated_at DESC LIMIT 1000').all();
  res.json(rows);
});

router.post('/admin/jobs/:id/retry', requirePermission('ops:manage'), (req, res) => {
  const r = db.prepare("UPDATE background_jobs SET status = 'queued', dead_letter = 0, attempts = attempts + 1, updated_at = ? WHERE id = ?")
    .run(nowIso(), req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'Job not found' });
  createAuditLog({ actor: req.user, action: 'job_retry', targetType: 'background_job', targetId: req.params.id, details: {} });
  res.json({ ok: true });
});

router.get('/admin/reports/builder', requirePermission('dashboard:view'), (req, res) => {
  const exam = String(req.query.exam || '');
  const rows = db.prepare(
    `SELECT u.exam,
      COUNT(DISTINCT u.id) AS users,
      COUNT(t.id) AS tasks,
      SUM(CASE WHEN t.status = 'completed' THEN 1 ELSE 0 END) AS completed
      FROM users u
      LEFT JOIN tasks t ON t.user_id = u.id
      GROUP BY u.exam`
  ).all().filter((r) => (exam ? r.exam === exam : true));
  res.json(rows.map((r) => ({
    ...r,
    conversion_pct: r.tasks ? Number(((r.completed / r.tasks) * 100).toFixed(2)) : 0,
  })));
});

router.post('/admin/segments', requirePermission('dashboard:view'), (req, res) => {
  const schema = z.object({ name: z.string().min(2), criteria: z.record(z.any()) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid segment payload' });
  const row = db.prepare('INSERT INTO segments (name, criteria_json, created_by, created_at) VALUES (?, ?, ?, ?)')
    .run(parsed.data.name, JSON.stringify(parsed.data.criteria), req.user.id, nowIso());
  createAuditLog({ actor: req.user, action: 'segment_create', targetType: 'segment', targetId: row.lastInsertRowid, details: parsed.data.criteria });
  res.status(201).json({ ok: true, id: row.lastInsertRowid });
});

router.get('/admin/segments', requirePermission('dashboard:view'), (_req, res) => {
  const rows = db.prepare('SELECT id, name, criteria_json, created_by, created_at FROM segments ORDER BY created_at DESC').all();
  res.json(rows.map((r) => ({ ...r, criteria: parseJsonSafe(r.criteria_json, {}) })));
});

router.post('/admin/exports/schedule', requirePermission('dashboard:view'), (req, res) => {
  const schema = z.object({
    target: z.enum(['csv', 'sheets', 's3']),
    format: z.enum(['csv', 'json']).optional(),
    schedule_cron: z.string().min(5),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid schedule payload' });
  const row = db.prepare('INSERT INTO scheduled_exports (target, format, schedule_cron, status, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(parsed.data.target, parsed.data.format || 'csv', parsed.data.schedule_cron, 'active', req.user.id, nowIso());
  createAuditLog({ actor: req.user, action: 'export_schedule_create', targetType: 'scheduled_export', targetId: row.lastInsertRowid, details: parsed.data });
  res.status(201).json({ ok: true, id: row.lastInsertRowid });
});

router.get('/admin/privacy/requests', requirePermission('audit:view'), (_req, res) => {
  const rows = db.prepare('SELECT * FROM privacy_requests ORDER BY created_at DESC').all();
  res.json(rows);
});

router.post('/admin/privacy/requests', requirePermission('audit:view'), (req, res) => {
  const schema = z.object({
    user_id: z.number().int().positive(),
    request_type: z.enum(['export', 'delete', 'anonymize']),
    notes: z.string().max(1000).optional().nullable(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid privacy request payload' });
  const row = db.prepare('INSERT INTO privacy_requests (user_id, request_type, status, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(parsed.data.user_id, parsed.data.request_type, 'open', parsed.data.notes || null, nowIso(), nowIso());
  createAuditLog({ actor: req.user, action: 'privacy_request_create', targetType: 'privacy_request', targetId: row.lastInsertRowid, details: parsed.data });
  res.status(201).json({ ok: true, id: row.lastInsertRowid });
});

router.post('/admin/privacy/requests/:id/process', requirePermission('audit:view'), requireElevatedAccess, (req, res) => {
  const schema = z.object({ status: z.enum(['resolved', 'rejected']), note: z.string().optional().nullable() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid payload' });
  const row = db.prepare('SELECT id, user_id, request_type FROM privacy_requests WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Request not found' });
  if (row.request_type === 'delete') {
    const approvalId = Number(req.headers['x-dual-approval-id'] || 0);
    const approval = db.prepare('SELECT status, action FROM dual_approval_requests WHERE id = ?').get(approvalId);
    if (!approval || approval.status !== 'approved' || approval.action !== 'delete_user') {
      return res.status(403).json({ error: 'Dual approval is required for delete privacy requests' });
    }
  }
  if (row.request_type === 'anonymize' && parsed.data.status === 'resolved') {
    const anon = `anon-${row.user_id}-${Date.now()}@deleted.local`;
    db.prepare(
      "UPDATE users SET email = ?, name = 'Anonymized User', exam = 'N/A', is_active = 0, token_version = token_version + 1 WHERE id = ?"
    ).run(anon, row.user_id);
  }
  if (row.request_type === 'delete' && parsed.data.status === 'resolved') {
    db.prepare('DELETE FROM users WHERE id = ?').run(row.user_id);
  }
  db.prepare('UPDATE privacy_requests SET status = ?, notes = ?, updated_at = ? WHERE id = ?')
    .run(parsed.data.status, parsed.data.note || null, nowIso(), req.params.id);
  createAuditLog({ actor: req.user, action: 'privacy_request_process', targetType: 'privacy_request', targetId: req.params.id, details: parsed.data });
  res.json({ ok: true });
});

router.get('/user/data-export', (req, res) => {
  const format = String(req.query.format || 'json');
  const data = userSummaryById(req.user.id);
  if (format === 'csv') {
    const flat = [
      ['id', data.user.id],
      ['email', data.user.email],
      ['name', data.user.name],
      ['exam', data.user.exam],
      ['role', data.user.role],
      ['is_active', data.user.is_active],
    ];
    const csv = `field,value\n${flat.map(([k, v]) => `"${k}","${String(v).replace(/"/g, '""')}"`).join('\n')}\n`;
    res.setHeader('content-type', 'text/csv');
    return res.send(csv);
  }
  return res.json(data);
});

router.get('/admin/notifications/templates', requirePermission('support:manage'), (_req, res) => {
  const rows = db.prepare('SELECT id, name, title_template, body_template, created_by, created_at FROM notification_templates ORDER BY name').all();
  res.json(rows);
});

router.post('/admin/notifications/templates', requirePermission('support:manage'), (req, res) => {
  const schema = z.object({ name: z.string().min(2), title_template: z.string().min(2), body_template: z.string().min(2) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid template payload' });
  db.prepare(
    `INSERT INTO notification_templates (name, title_template, body_template, created_by, created_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(name) DO UPDATE SET title_template = excluded.title_template, body_template = excluded.body_template`
  ).run(parsed.data.name, parsed.data.title_template, parsed.data.body_template, req.user.id, nowIso());
  createAuditLog({ actor: req.user, action: 'notification_template_upsert', targetType: 'notification_template', targetId: parsed.data.name, details: {} });
  res.json({ ok: true });
});

router.post('/admin/announcements', requirePermission('support:manage'), (req, res) => {
  const schema = z.object({
    title: z.string().min(2),
    body: z.string().min(2),
    segment: z.string().optional().nullable(),
    starts_at: z.string().optional().nullable(),
    ends_at: z.string().optional().nullable(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid announcement payload' });
  const row = db.prepare(
    'INSERT INTO announcements (title, body, segment, starts_at, ends_at, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(parsed.data.title, parsed.data.body, parsed.data.segment || null, parsed.data.starts_at || null, parsed.data.ends_at || null, req.user.id, nowIso());
  createAuditLog({ actor: req.user, action: 'announcement_create', targetType: 'announcement', targetId: row.lastInsertRowid, details: parsed.data });
  res.status(201).json({ ok: true, id: row.lastInsertRowid });
});

router.get('/admin/support/tickets', requirePermission('support:manage'), (_req, res) => {
  const rows = db.prepare('SELECT * FROM support_tickets ORDER BY updated_at DESC').all();
  res.json(rows.map((r) => ({ ...r, messages: parseJsonSafe(r.messages_json, []) })));
});

router.post('/support/tickets', (req, res) => {
  const schema = z.object({ subject: z.string().min(2), message: z.string().min(2), priority: z.enum(['low', 'medium', 'high']).optional() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid ticket payload' });
  const messages = [{ at: nowIso(), by: req.user.id, body: parsed.data.message }];
  const row = db.prepare(
    'INSERT INTO support_tickets (user_id, subject, status, priority, messages_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(req.user.id, parsed.data.subject, 'open', parsed.data.priority || 'medium', JSON.stringify(messages), nowIso(), nowIso());
  res.status(201).json({ ok: true, id: row.lastInsertRowid });
});

router.post('/admin/support/tickets/:id/reply', requirePermission('support:manage'), (req, res) => {
  const schema = z.object({ message: z.string().min(2), macro_used: z.string().optional().nullable(), status: z.enum(['open', 'pending', 'resolved', 'escalated']).optional() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid payload' });
  const t = db.prepare('SELECT id, messages_json FROM support_tickets WHERE id = ?').get(req.params.id);
  if (!t) return res.status(404).json({ error: 'Ticket not found' });
  const messages = parseJsonSafe(t.messages_json, []);
  messages.push({ at: nowIso(), by: req.user.id, body: parsed.data.message, macro_used: parsed.data.macro_used || null });
  db.prepare('UPDATE support_tickets SET messages_json = ?, macro_used = ?, status = COALESCE(?, status), updated_at = ? WHERE id = ?')
    .run(JSON.stringify(messages), parsed.data.macro_used || null, parsed.data.status || null, nowIso(), req.params.id);
  createAuditLog({ actor: req.user, action: 'support_ticket_reply', targetType: 'support_ticket', targetId: req.params.id, details: {} });
  res.json({ ok: true });
});

router.get('/admin/support/macros', requirePermission('support:manage'), (_req, res) => {
  const rows = db.prepare('SELECT * FROM support_macros ORDER BY name').all();
  res.json(rows);
});

router.post('/admin/support/macros', requirePermission('support:manage'), (req, res) => {
  const schema = z.object({ name: z.string().min(2), body: z.string().min(2) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid macro payload' });
  db.prepare(
    `INSERT INTO support_macros (name, body, created_by, created_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(name) DO UPDATE SET body = excluded.body`
  ).run(parsed.data.name, parsed.data.body, req.user.id, nowIso());
  createAuditLog({ actor: req.user, action: 'support_macro_upsert', targetType: 'support_macro', targetId: parsed.data.name, details: {} });
  res.json({ ok: true });
});

router.post('/admin/security/elevated-access', requirePermission('users:edit'), (req, res) => {
  const schema = z.object({ reason: z.string().min(8), ttl_minutes: z.number().int().min(1).max(30).optional() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid payload' });
  const token = `elev_${crypto.randomBytes(16).toString('hex')}`;
  const expires = new Date(Date.now() + (parsed.data.ttl_minutes || 10) * 60 * 1000).toISOString();
  const row = db.prepare(
    'INSERT INTO elevated_access_requests (actor_user_id, reason, token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)'
  ).run(req.user.id, parsed.data.reason, token, expires, nowIso());
  createAuditLog({ actor: req.user, action: 'elevated_access_request', targetType: 'elevated_access', targetId: row.lastInsertRowid, details: { reason: parsed.data.reason } });
  res.status(201).json({ ok: true, token, expires_at: expires });
});

router.post('/admin/security/dual-approval', requirePermission('users:edit'), (req, res) => {
  const schema = z.object({ action: z.string().min(2), payload: z.record(z.any()) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid payload' });
  const row = db.prepare(
    'INSERT INTO dual_approval_requests (action, payload_json, created_by, approvals_json, status, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(parsed.data.action, JSON.stringify(parsed.data.payload), req.user.id, JSON.stringify([req.user.id]), 'pending', nowIso());
  createAuditLog({ actor: req.user, action: 'dual_approval_request_create', targetType: 'dual_approval', targetId: row.lastInsertRowid, details: parsed.data });
  res.status(201).json({ ok: true, id: row.lastInsertRowid });
});

router.post('/admin/security/dual-approval/:id/approve', requirePermission('users:edit'), (req, res) => {
  const row = db.prepare('SELECT * FROM dual_approval_requests WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Request not found' });
  const approvals = parseJsonSafe(row.approvals_json, []);
  if (!approvals.includes(req.user.id)) approvals.push(req.user.id);
  const status = approvals.length >= 2 ? 'approved' : 'pending';
  db.prepare('UPDATE dual_approval_requests SET approvals_json = ?, status = ?, approved_at = CASE WHEN ? = ? THEN ? ELSE approved_at END WHERE id = ?')
    .run(JSON.stringify(approvals), status, status, 'approved', nowIso(), req.params.id);
  createAuditLog({ actor: req.user, action: 'dual_approval_approve', targetType: 'dual_approval', targetId: req.params.id, details: { status } });
  res.json({ ok: true, status, approvals_count: approvals.length });
});

router.get('/admin/security/dual-approval', requirePermission('users:edit'), (_req, res) => {
  const rows = db.prepare('SELECT * FROM dual_approval_requests ORDER BY created_at DESC').all();
  res.json(rows.map((r) => ({ ...r, approvals: parseJsonSafe(r.approvals_json, []), payload: parseJsonSafe(r.payload_json, {}) })));
});

router.get('/admin/security/secrets/rotations', requirePermission('ops:manage'), (_req, res) => {
  const rows = db.prepare('SELECT * FROM secret_rotations ORDER BY created_at DESC').all();
  res.json(rows);
});

router.post('/admin/security/secrets/rotations', requirePermission('ops:manage'), (req, res) => {
  const schema = z.object({ secret_name: z.string().min(2) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid payload' });
  const row = db.prepare(
    'INSERT INTO secret_rotations (secret_name, status, requested_by, created_at) VALUES (?, ?, ?, ?)'
  ).run(parsed.data.secret_name, 'pending', req.user.id, nowIso());
  createAuditLog({ actor: req.user, action: 'secret_rotation_request', targetType: 'secret_rotation', targetId: row.lastInsertRowid, details: parsed.data });
  res.status(201).json({ ok: true, id: row.lastInsertRowid });
});

router.post('/admin/security/secrets/rotations/:id/complete', requirePermission('ops:manage'), requireElevatedAccess, (req, res) => {
  const r = db.prepare("UPDATE secret_rotations SET status = 'completed', completed_by = ?, completed_at = ? WHERE id = ?")
    .run(req.user.id, nowIso(), req.params.id);
  if (!r.changes) return res.status(404).json({ error: 'Rotation request not found' });
  createAuditLog({ actor: req.user, action: 'secret_rotation_complete', targetType: 'secret_rotation', targetId: req.params.id, details: {} });
  res.json({ ok: true });
});

router.get('/admin/policy-matrix', requirePermission('audit:view'), (_req, res) => {
  const roles = db.prepare('SELECT role, permissions_json FROM role_permissions ORDER BY role').all();
  res.json(roles.map((r) => ({ role: r.role, permissions: parseJsonSafe(r.permissions_json, []) })));
});

router.get('/admin/me/permissions', authRequired, (req, res) => {
  res.json({ role: req.user.role, permissions: getRolePermissions(req.user.role) });
});

module.exports = router;
