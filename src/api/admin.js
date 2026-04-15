const express = require('express');
const { z } = require('zod');
const db = require('../db');
const { authRequired } = require('../middleware/auth');
const { createAuditLog, requireDualApproval, requireElevatedAccess } = require('../services/admin');
const { processPdfIngestion } = require('../services/pdf-processor');
const { buildUser360 } = require('../services/analytics');

const router = express.Router();
router.use(authRequired);

function requireSuperadmin(req, res, next) {
  if (String(req.user?.role || '').toLowerCase() !== 'superadmin') {
    return res.status(403).json({ error: 'Superadmin access required' });
  }
  return next();
}

router.use(requireSuperadmin);

function nowIso() {
  return new Date().toISOString();
}

function audit(req, action, targetType, targetId, details = {}) {
  createAuditLog({
    actor: req.user,
    action,
    targetType,
    targetId,
    details: {
      ...details,
      ip: req.ip,
      timestamp: nowIso(),
    },
  });
}

router.get('/panel/dashboard', (_req, res) => {
  const releaseControls = db.prepare('SELECT control_key, enabled, reason, updated_at FROM release_controls ORDER BY control_key').all();
  const users = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  const active = db.prepare('SELECT COUNT(*) AS c FROM users WHERE is_active = 1').get().c;
  const content = db.prepare('SELECT COUNT(*) AS c FROM content_library').get().c;
  const apiLogs = db.prepare("SELECT COUNT(*) AS c FROM api_request_logs WHERE created_at >= datetime('now','-1 day')").get().c;
  res.json({
    sidebarTabs: ['User Command Center', 'Content & PDF Lab', 'System Health', 'Audit Vault', 'Global Settings'],
    kpis: { users, activeUsers: active, contentItems: content, apiRequests24h: apiLogs },
    releaseControls,
  });
});

router.get('/panel/users', (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  const rows = db.prepare(
    'SELECT id, email, name, exam, role, package_name, is_active, last_login_at, created_at FROM users ORDER BY created_at DESC'
  ).all();
  const filtered = q ? rows.filter((r) => `${r.email} ${r.name}`.toLowerCase().includes(q)) : rows;
  res.json(filtered);
});

router.get('/panel/users/:id/deep-dive', (req, res) => {
  const userId = Number(req.params.id);
  if (!userId) return res.status(400).json({ error: 'Invalid user id' });
  const user = db.prepare(
    `SELECT u.id, u.email, u.name, u.exam, u.package_name, u.is_active, u.onboarding_completed,
            p.onboarding_data_json
       FROM users u LEFT JOIN profiles p ON p.user_id = u.id WHERE u.id = ?`
  ).get(userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const moods = db.prepare('SELECT mood, note, created_at FROM moods WHERE user_id = ? ORDER BY created_at DESC LIMIT 200').all(userId);
  const apiLogs = db.prepare('SELECT method, endpoint, status_code, latency_ms, created_at FROM api_request_logs WHERE user_id = ? ORDER BY created_at ASC').all(userId);
  const mockTests = db.prepare('SELECT id, name, score, total, created_at FROM mock_tests WHERE user_id = ? ORDER BY created_at DESC LIMIT 200').all(userId);
  const tasks = db.prepare('SELECT id, status, suggested_time, actual_time, created_at FROM tasks WHERE user_id = ? ORDER BY created_at DESC LIMIT 500').all(userId);
  const errorJournal = db.prepare('SELECT topic, question, created_at FROM error_journal WHERE user_id = ? ORDER BY created_at DESC LIMIT 300').all(userId);
  const analytics = buildUser360({ user, moods, apiLogs, mockTests, tasks, errorJournal });
  let onboardingData = {};
  try {
    onboardingData = JSON.parse(user.onboarding_data_json || '{}');
  } catch (_err) {}
  res.json({ ...analytics, onboarding_data: onboardingData });
});

router.patch('/panel/users/:id/access', (req, res) => {
  const schema = z.object({
    package_name: z.enum(['free', 'premium']).optional(),
    is_active: z.boolean().optional(),
  }).refine((data) => data.package_name !== undefined || data.is_active !== undefined, {
    message: 'At least one field is required',
  });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({
      error: 'Validation failed',
      details: parsed.error.issues,
    });
  }
  const fields = [];
  const values = [];
  if (parsed.data.package_name) {
    fields.push('package_name = ?');
    values.push(parsed.data.package_name);
  }
  if (typeof parsed.data.is_active === 'boolean') {
    fields.push('is_active = ?');
    values.push(parsed.data.is_active ? 1 : 0);
  }
  values.push(Number(req.params.id));
  const result = db.prepare(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  if (!result.changes) return res.status(404).json({ error: 'User not found' });
  audit(req, 'admin_user_access_update', 'user', req.params.id, parsed.data);
  return res.json({ ok: true });
});

router.get('/panel/release-controls', (_req, res) => {
  const rows = db.prepare('SELECT control_key, enabled, reason, updated_by, updated_at FROM release_controls ORDER BY control_key').all();
  res.json(rows);
});

router.post('/panel/release-controls', (req, res) => {
  const schema = z.object({ control_key: z.enum(['maintenance_mode', 'global_kill_switch']), enabled: z.boolean(), reason: z.string().max(500).optional() });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ error: 'Invalid payload' });
  db.prepare(
    `INSERT INTO release_controls (control_key, enabled, reason, updated_by, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(control_key) DO UPDATE SET enabled = excluded.enabled, reason = excluded.reason, updated_by = excluded.updated_by, updated_at = excluded.updated_at`
  ).run(parsed.data.control_key, parsed.data.enabled ? 1 : 0, parsed.data.reason || '', req.user.id, nowIso());
  audit(req, 'admin_release_control_update', 'release_control', parsed.data.control_key, parsed.data);
  return res.json({ ok: true });
});

router.get('/panel/audit-vault', (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  const action = String(req.query.action || '').trim();
  const rows = db.prepare(
    'SELECT id, actor_user_id, actor_email, action, target_type, target_id, details_json, created_at FROM audit_log ORDER BY id DESC LIMIT 2000'
  ).all();
  const filtered = rows.filter((r) => {
    if (action && r.action !== action) return false;
    if (!q) return true;
    return `${r.action} ${r.target_type} ${r.target_id || ''} ${r.actor_email || ''}`.toLowerCase().includes(q);
  });
  res.json(filtered);
});

router.get('/panel/settings', (_req, res) => {
  const apiLimits = db.prepare("SELECT config_value FROM config_settings WHERE config_key = 'api.limits'").get();
  const aiQuotas = db.prepare('SELECT daily_quota, per_user_quota, per_feature_quota FROM ai_guardrails WHERE id = 1').get();
  const templates = db.prepare('SELECT id, name, title_template, body_template, created_at FROM notification_templates ORDER BY name').all();
  res.json({
    api_limits: apiLimits ? JSON.parse(apiLimits.config_value || '{}') : {},
    ai_quotas: aiQuotas || {},
    notification_templates: templates,
  });
});

router.post('/panel/settings', (req, res) => {
  const schema = z.object({
    api_limits: z.record(z.any()).optional(),
    ai_quotas: z.object({ daily_quota: z.number().int().positive(), per_user_quota: z.number().int().positive(), per_feature_quota: z.number().int().positive() }).optional(),
    notification_template: z.object({ name: z.string().min(2), title_template: z.string().min(1), body_template: z.string().min(1) }).optional(),
  });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ error: 'Invalid settings payload' });
  const now = nowIso();
  const p = parsed.data;
  if (p.api_limits) {
    db.prepare(
      `INSERT INTO config_settings (config_key, config_value, validation_rule, updated_by, updated_at)
       VALUES (?, ?, 'json', ?, ?)
       ON CONFLICT(config_key) DO UPDATE SET config_value = excluded.config_value, updated_by = excluded.updated_by, updated_at = excluded.updated_at`
    ).run('api.limits', JSON.stringify(p.api_limits), req.user.id, now);
  }
  if (p.ai_quotas) {
    db.prepare(
      'UPDATE ai_guardrails SET daily_quota = ?, per_user_quota = ?, per_feature_quota = ?, updated_by = ?, updated_at = ? WHERE id = 1'
    ).run(p.ai_quotas.daily_quota, p.ai_quotas.per_user_quota, p.ai_quotas.per_feature_quota, req.user.id, now);
  }
  if (p.notification_template) {
    db.prepare(
      `INSERT INTO notification_templates (name, title_template, body_template, created_by, created_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(name) DO UPDATE SET title_template = excluded.title_template, body_template = excluded.body_template`
    ).run(p.notification_template.name, p.notification_template.title_template, p.notification_template.body_template, req.user.id, now);
  }
  audit(req, 'admin_global_settings_update', 'config', 'global', parsed.data);
  return res.json({ ok: true });
});

router.get('/panel/pdf-lab', (_req, res) => {
  const rows = db.prepare(
    "SELECT id, course_key, content_type, title, status, created_at, updated_at FROM content_library WHERE content_type IN ('book','mock_test','question_bank') ORDER BY updated_at DESC LIMIT 500"
  ).all();
  res.json(rows);
});

router.post('/panel/pdf-lab/ingest', async (req, res) => {
  const schema = z.object({
    course_key: z.string().min(2),
    title: z.string().min(2),
    description: z.string().max(1000).optional().nullable(),
    source_file_name: z.string().min(1),
    source_mime_type: z.string().optional().nullable(),
    file_base64: z.string().min(10),
    metadata: z.record(z.any()).optional(),
  });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ error: 'Invalid PDF ingestion payload' });

  try {
    const buffer = Buffer.from(parsed.data.file_base64, 'base64');
    const processed = await processPdfIngestion({
      fileBuffer: buffer,
      sourceFileName: parsed.data.source_file_name,
      sourceMimeType: parsed.data.source_mime_type || 'application/pdf',
      metadata: parsed.data.metadata || {},
    });
    const now = nowIso();
    const row = db.prepare(
      'INSERT INTO content_library (course_key, content_type, title, description, data_json, status, updated_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(
      parsed.data.course_key,
      'question_bank',
      parsed.data.title,
      parsed.data.description || null,
      JSON.stringify(processed.data_json),
      'active',
      req.user.id,
      now,
      now
    );
    audit(req, 'admin_pdf_ingest', 'content', row.lastInsertRowid, {
      question_count: processed.questionCount,
      used_ai_fallback: processed.usedAiFallback,
      source_file_name: parsed.data.source_file_name,
    });
    return res.status(201).json({
      ok: true,
      id: row.lastInsertRowid,
      question_count: processed.questionCount,
      used_ai_fallback: processed.usedAiFallback,
    });
  } catch (err) {
    return res.status(400).json({ error: err?.message || 'Failed to ingest PDF' });
  }
});

router.delete('/panel/content/:id', requireElevatedAccess, requireDualApproval('delete_course'), (req, res) => {
  const row = db.prepare('DELETE FROM content_library WHERE id = ?').run(req.params.id);
  if (!row.changes) return res.status(404).json({ error: 'Content not found' });
  audit(req, 'admin_course_delete', 'content', req.params.id, {});
  return res.json({ ok: true });
});

router.get('/panel/users/export-full', requireElevatedAccess, requireDualApproval('export_full_user_db'), (req, res) => {
  const rows = db.prepare('SELECT id, email, name, exam, role, package_name, is_active, created_at FROM users ORDER BY id').all();
  audit(req, 'admin_full_user_export', 'user', 'all', { count: rows.length });
  return res.json({ ok: true, count: rows.length, users: rows });
});

module.exports = router;
