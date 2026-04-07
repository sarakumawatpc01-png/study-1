const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const dataRoot = process.env.DATA_ROOT_DIR || (process.env.VERCEL ? '/tmp' : process.cwd());
const dataDir = path.join(dataRoot, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const dbPath = path.join(dataDir, 'app.db');
const db = new Database(dbPath);
db.pragma('foreign_keys = ON');

const schemaSql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
db.exec(schemaSql);

function safeExec(sql) {
  try {
    db.exec(sql);
  } catch (err) {
    const msg = String(err?.message || '').toLowerCase();
    if (msg.includes('duplicate column name')) return;
    // eslint-disable-next-line no-console
    console.error('Migration SQL failed:', sql, err.message);
    throw err;
  }
}

safeExec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'student';");
safeExec("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1;");
safeExec("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;");
safeExec("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0;");
safeExec("ALTER TABLE users ADD COLUMN last_login_at TEXT;");
safeExec("ALTER TABLE users ADD COLUMN package_name TEXT NOT NULL DEFAULT 'free';");
safeExec("ALTER TABLE users ADD COLUMN platform_language TEXT NOT NULL DEFAULT 'Hinglish';");
safeExec("ALTER TABLE users ADD COLUMN test_language TEXT NOT NULL DEFAULT 'English';");

safeExec("ALTER TABLE reports ADD COLUMN priority TEXT NOT NULL DEFAULT 'medium';");
safeExec("ALTER TABLE reports ADD COLUMN assigned_to INTEGER;");
safeExec("ALTER TABLE reports ADD COLUMN sla_due_at TEXT;");
safeExec("ALTER TABLE reports ADD COLUMN resolution_template TEXT;");
safeExec("ALTER TABLE reports ADD COLUMN internal_note TEXT;");
safeExec("ALTER TABLE webhook_events ADD COLUMN provider TEXT;");
safeExec("ALTER TABLE webhook_events ADD COLUMN event_id TEXT;");
safeExec("ALTER TABLE webhook_events ADD COLUMN signature_valid INTEGER NOT NULL DEFAULT 0;");

db.prepare(
  'INSERT OR IGNORE INTO role_permissions (role, permissions_json, updated_at) VALUES (?, ?, ?)'
).run('superadmin', JSON.stringify(['*']), new Date().toISOString());
db.prepare(
  'INSERT OR IGNORE INTO role_permissions (role, permissions_json, updated_at) VALUES (?, ?, ?)'
).run(
  'admin',
  JSON.stringify([
    'dashboard:view',
    'users:view',
    'users:edit',
    'reports:view',
    'reports:triage',
    'content:view',
    'content:edit',
    'audit:view',
    'ai:manage',
    'api:manage',
    'ops:manage',
    'payments:settings',
    'payments:test',
    'payments:webhooks:retry',
    'payments:webhooks:validate',
    'support:manage',
  ]),
  new Date().toISOString()
);
db.prepare(
  'INSERT OR IGNORE INTO role_permissions (role, permissions_json, updated_at) VALUES (?, ?, ?)'
).run('support', JSON.stringify(['reports:view', 'reports:triage', 'users:view', 'support:manage']), new Date().toISOString());
db.prepare(
  'INSERT OR IGNORE INTO role_permissions (role, permissions_json, updated_at) VALUES (?, ?, ?)'
).run('content', JSON.stringify(['content:view', 'content:edit', 'reports:view']), new Date().toISOString());

db.prepare(
  'INSERT OR IGNORE INTO ai_guardrails (id, pii_redaction, moderation_threshold, fallback_behavior, daily_quota, per_user_quota, per_feature_quota, updated_at) VALUES (1, 1, 0.7, ?, 10000, 100, 1000, ?)'
).run('safe_summary', new Date().toISOString());

db.prepare(
  'INSERT OR IGNORE INTO release_controls (control_key, enabled, reason, updated_at) VALUES (?, 0, ?, ?)'
).run('maintenance_mode', '', new Date().toISOString());
db.prepare(
  'INSERT OR IGNORE INTO release_controls (control_key, enabled, reason, updated_at) VALUES (?, 0, ?, ?)'
).run('global_kill_switch', '', new Date().toISOString());

db.prepare(
  'INSERT OR IGNORE INTO retention_policies (policy_key, keep_days, enabled, updated_at) VALUES (?, ?, 1, ?)'
).run('api_request_logs', 30, new Date().toISOString());
db.prepare(
  'INSERT OR IGNORE INTO retention_policies (policy_key, keep_days, enabled, updated_at) VALUES (?, ?, 1, ?)'
).run('audit_log', 365, new Date().toISOString());

function ensureRolePermissions(role, requiredPermissions) {
  const row = db.prepare('SELECT permissions_json FROM role_permissions WHERE role = ?').get(role);
  if (!row) return;
  let existing = [];
  try {
    existing = JSON.parse(row.permissions_json || '[]');
  } catch (_err) {
    existing = [];
  }
  if (existing.includes('*')) return;
  const merged = Array.from(new Set([...existing, ...requiredPermissions]));
  db.prepare('UPDATE role_permissions SET permissions_json = ?, updated_at = ? WHERE role = ?')
    .run(JSON.stringify(merged), new Date().toISOString(), role);
}

ensureRolePermissions('admin', ['payments:settings', 'payments:test', 'payments:webhooks:retry', 'payments:webhooks:validate']);

db.__path = dbPath;

module.exports = db;
