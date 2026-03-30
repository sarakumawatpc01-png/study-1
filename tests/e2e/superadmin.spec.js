const { test, expect } = require('@playwright/test');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

function db() {
  return new Database(path.join(process.cwd(), 'data', 'app.db'));
}

async function signupAndPromote(request, role) {
  const email = `${role}-${crypto.randomUUID()}@example.com`;
  const signup = await request.post('/api/auth/signup', {
    data: { email, password: 'StrongPass123', name: role, exam: 'SSC CGL' },
  });
  expect(signup.status()).toBe(201);
  const login = await request.post('/api/auth/login', { data: { email, password: 'StrongPass123' } });
  expect(login.status()).toBe(200);
  const body = await login.json();
  const token = body.token;
  const conn = db();
  conn.prepare('UPDATE users SET role = ?, mfa_enabled = 1 WHERE email = ?').run(role, email);
  conn.close();
  return { email, token };
}

test('superadmin payment/ops tab renders and supports interaction flows', async ({ page, request }) => {
  const admin = await signupAndPromote(request, 'admin');
  await page.addInitScript((token) => localStorage.setItem('study_token', token), admin.token);
  await page.goto('/');
  await page.evaluate(async () => { await launch(); });
  await page.waitForSelector('#app.on', { timeout: 15000 });
  await page.evaluate(() => go('superadmin'));
  await page.click('.tab:has-text("⚙️ Flags & Ops")');
  await expect(page.locator('#sa-ops')).toBeVisible();
  await page.click('text=Payments');
  await expect(page.locator('#sa-pay-test-btn')).toBeVisible();
  await expect(page.locator('#sa-pay-save-btn')).toBeVisible();
  await page.click('#sa-pay-test-btn');
  await expect(page.locator('#sa-pay-test-result')).toContainText(/Testing|AUTH|FAILED|OK|Connection/i);
});

test('support role sees payment settings disabled state', async ({ page, request }) => {
  const support = await signupAndPromote(request, 'support');
  await page.addInitScript((token) => localStorage.setItem('study_token', token), support.token);
  await page.goto('/');
  await page.evaluate(async () => { await launch(); });
  await page.waitForSelector('#app.on', { timeout: 15000 });
  await page.evaluate(() => go('superadmin'));
  await page.click('.tab:has-text("⚙️ Flags & Ops")');
  await expect(page.locator('#sa-ops')).toBeVisible();
  await page.click('text=Payments');
  await expect(page.locator('#sa-pay-settings-warning')).toBeVisible();
  await expect(page.locator('#sa-pay-save-btn')).toBeDisabled();
});
