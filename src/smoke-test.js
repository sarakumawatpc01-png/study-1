const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
process.env.JWT_SECRET = process.env.JWT_SECRET || 'smoke-test-secret';
process.env.AUDIT_SIGNING_SECRET = process.env.AUDIT_SIGNING_SECRET || 'smoke-test-audit-secret';
const app = require('./server');
const db = require('./db');

function req(method, path, body, token, headers = {}) {
  const payload = body ? JSON.stringify(body) : null;
  return new Promise((resolve, reject) => {
    const r = http.request(
      {
        host: '127.0.0.1',
        port: global.__PORT__,
        method,
        path,
        headers: {
          'content-type': 'application/json',
          ...(payload ? { 'content-length': Buffer.byteLength(payload) } : {}),
          ...(token ? { authorization: `Bearer ${token}` } : {}),
          ...headers,
        },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          let json = {};
          try {
            json = data ? JSON.parse(data) : {};
          } catch (e) {
            console.error('Failed to parse response JSON for', method, path, e.message);
            json = { raw: data };
          }
          resolve({ status: res.statusCode, body: json, raw: data });
        });
      }
    );
    r.on('error', reject);
    if (payload) r.write(payload);
    r.end();
  });
}

async function run() {
  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  global.__PORT__ = server.address().port;

  const testEmail = `user-${crypto.randomUUID()}@example.com`;
  const adminEmail = `admin-${crypto.randomUUID()}@example.com`;
  const adminPassword = crypto.randomBytes(12).toString('hex');

  const signup = await req('POST', '/api/auth/signup', {
    email: testEmail,
    password: 'StrongPass123',
    name: 'Rahul',
    exam: 'SSC CGL',
  });
  if (signup.status !== 201 || !signup.body.token) throw new Error('Signup failed');

  const userToken = signup.body.token;
  const me = await req('GET', '/api/auth/me', null, userToken);
  if (me.status !== 200 || me.body.email !== testEmail) throw new Error('Auth me failed');

  const report = await req('POST', '/api/reports', {
    category: 'question',
    title: 'Answer key mismatch',
    description: 'correct answer seems wrong for option B',
    priority: 'high',
  }, userToken);
  if (report.status !== 201 || !report.body.id) throw new Error('Report create failed');

  const contentForbidden = await req('GET', '/api/admin/content', null, userToken);
  if (contentForbidden.status !== 403) throw new Error('Student unexpectedly accessed admin content');

  const adminPass = await bcrypt.hash(adminPassword, 10);
  const createdAt = new Date().toISOString();
  const adminInsert = db.prepare(
    'INSERT INTO users (email, password_hash, name, exam, role, is_active, token_version, mfa_enabled, created_at) VALUES (?, ?, ?, ?, ?, 1, 0, 1, ?)'
  ).run(adminEmail, adminPass, 'Admin User', 'UPSC', 'superadmin', createdAt);
  db.prepare('INSERT INTO profiles (user_id, mood, readiness_score) VALUES (?, ?, ?)').run(adminInsert.lastInsertRowid, 'Normal / Okay', 50);

  const adminLogin = await req('POST', '/api/auth/login', { email: adminEmail, password: adminPassword });
  if (adminLogin.status !== 200 || !adminLogin.body.token) throw new Error('Admin login failed');
  const adminToken = adminLogin.body.token;

  const dashboard = await req('GET', '/api/admin/dashboard', null, adminToken);
  if (dashboard.status !== 200 || !dashboard.body.kpis) throw new Error('Admin dashboard failed');

  const usersList = await req('GET', '/api/admin/users', null, adminToken);
  if (usersList.status !== 200 || !Array.isArray(usersList.body)) throw new Error('Admin users list failed');

  const contentCreate = await req('POST', '/api/admin/content', {
    course_key: 'ssc-cgl',
    content_type: 'course',
    title: 'Quant Basics',
    description: 'Course',
    status: 'draft',
    data: { level: 1 },
  }, adminToken);
  if (contentCreate.status !== 201 || !contentCreate.body.id) throw new Error('Content create failed');

  const contentVersions = await req('GET', `/api/admin/content/${contentCreate.body.id}/versions`, null, adminToken);
  if (contentVersions.status !== 200 || !Array.isArray(contentVersions.body)) throw new Error('Content versions failed');

  const promptCreate = await req('POST', '/api/admin/ai/prompts', {
    feature: 'report-triage',
    template: 'Analyze report',
    status: 'active',
  }, adminToken);
  if (promptCreate.status !== 201) throw new Error('AI prompt create failed');

  const apiKeyCreate = await req('POST', '/api/admin/api/keys', {
    name: 'smoke-key',
    rate_limit_per_min: 50,
    quota_per_day: 1000,
  }, adminToken);
  if (apiKeyCreate.status !== 201 || !apiKeyCreate.body.api_key) throw new Error('API key create failed');

  const flagSet = await req('POST', '/api/admin/feature-flags', {
    flag_key: 'new-dashboard',
    description: 'test',
    enabled: true,
    scope: 'global',
  }, adminToken);
  if (flagSet.status !== 200) throw new Error('Feature flag set failed');

  const configSet = await req('POST', '/api/admin/config', {
    config_key: 'ops.sample',
    config_value: { mode: 'safe' },
    validation_rule: 'json',
  }, adminToken);
  if (configSet.status !== 200) throw new Error('Config set failed');

  const elevated = await req('POST', '/api/admin/security/elevated-access', {
    reason: 'Smoke test admin action',
    ttl_minutes: 10,
  }, adminToken);
  if (elevated.status !== 201 || !elevated.body.token) throw new Error('Elevated access request failed');
  const elevatedToken = elevated.body.token;

  const disableUser = await req('POST', `/api/admin/users/${signup.body.user.id}/disable`, {}, adminToken, {
    'x-elevated-token': elevatedToken,
  });
  if (disableUser.status !== 200) throw new Error('Disable user failed');

  const loginDisabled = await req('POST', '/api/auth/login', {
    email: testEmail,
    password: 'StrongPass123',
  });
  if (loginDisabled.status !== 403) throw new Error('Disabled user login should fail');

  const audits = await req('GET', '/api/admin/audit', null, adminToken);
  if (audits.status !== 200 || !Array.isArray(audits.body)) throw new Error('Audit endpoint failed');

  const cleanup = db.transaction(() => {
    db.prepare("DELETE FROM users WHERE email IN (?, ?)").run(testEmail, adminEmail);
    db.prepare('DELETE FROM content_library WHERE title = ?').run('Quant Basics');
    db.prepare('DELETE FROM notification_templates WHERE name = ?').run('smoke-template');
    db.prepare('DELETE FROM feature_flags WHERE flag_key = ?').run('new-dashboard');
    db.prepare('DELETE FROM config_settings WHERE config_key = ?').run('ops.sample');
    db.prepare('DELETE FROM config_history WHERE config_key = ?').run('ops.sample');
    db.prepare('DELETE FROM api_keys WHERE name = ?').run('smoke-key');
    db.prepare('DELETE FROM ai_prompt_templates WHERE feature = ?').run('report-triage');
  });
  cleanup();

  await new Promise((resolve) => server.close(resolve));
  console.log('Smoke test passed');
}

run().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
