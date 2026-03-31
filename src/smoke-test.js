const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
process.env.JWT_SECRET = process.env.JWT_SECRET || 'smoke-test-secret';
process.env.AUDIT_SIGNING_SECRET = process.env.AUDIT_SIGNING_SECRET || 'smoke-test-audit-secret';
process.env.PAYMENT_CONFIG_ENCRYPTION_KEY = process.env.PAYMENT_CONFIG_ENCRYPTION_KEY || 'smoke-test-payment-key';
process.env.DATA_ROOT_DIR = process.env.DATA_ROOT_DIR || `/tmp/study-smoke-${process.pid}`;
const app = require('./server');
const db = require('./db');
const EXPECTED_ERROR_PATTERNS = [/Failed to parse response JSON for/];

const originalConsoleError = console.error;
const capturedErrors = [];
console.error = (...args) => {
  capturedErrors.push(args.map((v) => String(v)).join(' '));
  originalConsoleError(...args);
};

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
  if (me.body.role !== 'student' || !Array.isArray(me.body.permissions)) throw new Error('Auth me role/permissions payload missing');

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

  const paymentSet = await req('POST', '/api/admin/payments/settings', {
    provider: 'razorpay',
    mode: 'test',
    currency: 'INR',
    key_id: 'rzp_test_AbCdEf1234',
    key_secret: 'secretKey_123456',
    webhook_secret: 'whsec_123456',
  }, adminToken);
  if (paymentSet.status !== 200 || !paymentSet.body.settings?.has_key_secret) throw new Error('Payment settings save failed');

  const mistralSet = await req('POST', '/api/admin/ai/mistral-ocr', {
    enabled: true,
    model: 'mistral-ocr-latest',
    api_key: 'mistral_test_api_key_123456',
    base_url: 'https://api.mistral.ai',
  }, adminToken);
  if (mistralSet.status !== 200 || !mistralSet.body.settings?.has_api_key) throw new Error('Mistral OCR settings save failed');

  const mistralGet = await req('GET', '/api/admin/ai/mistral-ocr', null, adminToken);
  if (mistralGet.status !== 200 || mistralGet.body.api_key === 'mistral_test_api_key_123456') throw new Error('Mistral OCR masking failed');

  const openrouterSet = await req('POST', '/api/admin/ai/providers/openrouter', {
    enabled: true,
    model: 'openrouter/auto',
    api_key: 'openrouter_test_api_key_123456',
    base_url: 'https://openrouter.ai/api/v1',
  }, adminToken);
  if (openrouterSet.status !== 200 || !openrouterSet.body.settings?.has_api_key) throw new Error('OpenRouter settings save failed');

  const openrouterGet = await req('GET', '/api/admin/ai/providers/openrouter', null, adminToken);
  if (openrouterGet.status !== 200 || openrouterGet.body.api_key === 'openrouter_test_api_key_123456') throw new Error('OpenRouter masking failed');

  const allProviders = await req('GET', '/api/admin/ai/providers', null, adminToken);
  if (allProviders.status !== 200 || !allProviders.body?.openrouter || !allProviders.body?.sarvam || !allProviders.body?.deepseek) {
    throw new Error('AI providers listing failed');
  }

  const paymentRead = await req('GET', '/api/admin/payments/settings', null, adminToken);
  if (paymentRead.status !== 200 || paymentRead.body.settings?.key_secret === 'secretKey_123456') throw new Error('Payment settings masking failed');

  const paymentInConfig = await req('GET', '/api/admin/config', null, adminToken);
  const paymentCfg = Array.isArray(paymentInConfig.body) ? paymentInConfig.body.find((c) => c.config_key === 'payments.gateway') : null;
  if (!paymentCfg || String(paymentCfg.config_value || '').includes('secretKey_123456')) throw new Error('Config endpoint leaked payment secret');

  const paymentConnTest = await req('POST', '/api/admin/payments/test-connection', {
    source: 'payload',
    settings: {
      provider: 'cashfree',
      mode: 'test',
      currency: 'INR',
      key_id: 'cashfree-key-123',
      key_secret: 'cashfree-secret-123',
      webhook_secret: '',
    },
  }, adminToken);
  if (paymentConnTest.status !== 200 || !Array.isArray(paymentConnTest.body.diagnostics)) throw new Error('Payment connection test endpoint failed');

  const paymentRotate = await req('POST', '/api/admin/payments/rotate', {
    provider: 'cashfree',
    mode: 'test',
    currency: 'INR',
    key_id: 'cashfree-key-rot-123',
    key_secret: 'cashfree-secret-rot-123',
    webhook_secret: 'cashfree-wh-rot-123',
    reason: 'smoke rotate',
  }, adminToken);
  if (paymentRotate.status !== 201 || !paymentRotate.body.version) throw new Error('Payment rotate endpoint failed');

  const paymentVersions = await req('GET', '/api/admin/payments/versions', null, adminToken);
  if (paymentVersions.status !== 200 || !Array.isArray(paymentVersions.body) || paymentVersions.body.length < 1) throw new Error('Payment versions endpoint failed');

  const rollbackTarget = Number(paymentVersions.body[paymentVersions.body.length - 1]?.version_no || 0);
  if (rollbackTarget) {
    const paymentRollback = await req('POST', '/api/admin/payments/rollback', { version_no: rollbackTarget, reason: 'smoke rollback' }, adminToken);
    if (paymentRollback.status !== 200 || !paymentRollback.body.ok) throw new Error('Payment rollback endpoint failed');
  }

  const webhookPayload = JSON.stringify({ id: 'evt_smoke_1', amount: 100 });
  const webhookSig = crypto.createHmac('sha256', 'whsec_123456').update(webhookPayload).digest('hex');
  const webhookValidate = await req('POST', '/api/admin/payments/webhooks/validate', {
    provider: 'razorpay',
    event_id: `evt-${crypto.randomUUID()}`,
    event_name: 'payment.captured',
    signature: webhookSig,
    payload: JSON.parse(webhookPayload),
  }, adminToken);
  if (webhookValidate.status !== 200 || webhookValidate.body.ok !== true) throw new Error('Webhook validate endpoint failed');

  const publicWebhookValidate = await req('POST', '/api/ingest/payments/webhooks/validate', {
    provider: 'razorpay',
    event_id: `evt-public-${crypto.randomUUID()}`,
    event_name: 'payment.captured',
    signature: webhookSig,
    payload: JSON.parse(webhookPayload),
  });
  if (publicWebhookValidate.status !== 200 || publicWebhookValidate.body.ok !== true) throw new Error('Public webhook validate endpoint failed');

  const contentOcr = await req('POST', '/api/admin/content/upload-ocr', {
    course_key: 'ssc-cgl',
    content_type: 'book',
    title: 'Quant OCR Upload',
    description: 'OCR extract',
    source_file_name: 'quant.pdf',
    source_mime_type: 'application/pdf',
    raw_text: 'Sample OCR text',
    pages: [{ page: 1, text: 'Sample OCR text' }],
    metadata: { chapter: 'Algebra' },
  }, adminToken);
  if (contentOcr.status !== 201 || !contentOcr.body.id) throw new Error('OCR content upload failed');

  const contentList = await req('GET', '/api/admin/content', null, adminToken);
  const hasBook = Array.isArray(contentList.body) && contentList.body.some((c) => c.content_type === 'book');
  const hasCourse = Array.isArray(contentList.body) && contentList.body.some((c) => c.content_type === 'course');
  if (!hasBook || !hasCourse) throw new Error('Books/course listing failed after OCR upload');

  const webhookEvents = await req('GET', '/api/admin/webhooks/events', null, adminToken);
  if (webhookEvents.status !== 200 || !Array.isArray(webhookEvents.body)) throw new Error('Webhook events timeline failed');
  const firstWebhook = webhookEvents.body[0];
  if (firstWebhook?.id) {
    const transitions = await req('GET', `/api/admin/webhooks/${firstWebhook.id}/transitions`, null, adminToken);
    if (transitions.status !== 200 || !Array.isArray(transitions.body)) throw new Error('Webhook transitions endpoint failed');
  }

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
  if (!audits.body.some((a) => a.action === 'payment_gateway_update')) throw new Error('Payment audit enrichment missing');

  const unexpectedErrors = capturedErrors.filter((line) => !EXPECTED_ERROR_PATTERNS.some((pattern) => pattern.test(line)));
  if (unexpectedErrors.length) throw new Error(`Unexpected console.error logs: ${unexpectedErrors.join(' | ')}`);

  const cleanup = db.transaction(() => {
    db.prepare("DELETE FROM users WHERE email IN (?, ?)").run(testEmail, adminEmail);
    db.prepare('DELETE FROM content_library WHERE title = ?').run('Quant Basics');
    db.prepare('DELETE FROM notification_templates WHERE name = ?').run('smoke-template');
    db.prepare('DELETE FROM feature_flags WHERE flag_key = ?').run('new-dashboard');
    db.prepare('DELETE FROM config_settings WHERE config_key = ?').run('ops.sample');
    db.prepare('DELETE FROM config_history WHERE config_key = ?').run('ops.sample');
    db.prepare('DELETE FROM api_keys WHERE name = ?').run('smoke-key');
    db.prepare('DELETE FROM ai_prompt_templates WHERE feature = ?').run('report-triage');
    db.prepare('DELETE FROM content_library WHERE title = ?').run('Quant OCR Upload');
    db.prepare('DELETE FROM ai_model_routes WHERE feature = ?').run('ocr.ingest');
    db.prepare('DELETE FROM config_settings WHERE config_key = ?').run('ai.mistral_ocr');
    db.prepare('DELETE FROM config_history WHERE config_key = ?').run('ai.mistral_ocr');
    db.prepare("DELETE FROM config_settings WHERE config_key IN ('ai.provider.sarvam','ai.provider.openrouter','ai.provider.deepseek')").run();
    db.prepare("DELETE FROM config_history WHERE config_key IN ('ai.provider.sarvam','ai.provider.openrouter','ai.provider.deepseek')").run();
  });
  cleanup();

  await new Promise((resolve) => server.close(resolve));
  console.error = originalConsoleError;
  console.log('Smoke test passed');
}

run().catch((e) => {
  console.error = originalConsoleError;
  console.error(e.message);
  process.exit(1);
});
