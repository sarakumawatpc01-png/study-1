const fs = require('fs');
const path = require('path');

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function run() {
  const htmlPath = path.join(process.cwd(), 'public', 'index.html');
  const html = fs.readFileSync(htmlPath, 'utf8');

  assert(html.includes('/admin/payments/settings'), 'Superadmin UI should use dedicated payment settings API');
  assert(html.includes('/admin/payments/test-connection'), 'Superadmin UI should call payment test-connection endpoint');
  assert(html.includes("id=\"sa-pay-test-result\""), 'Superadmin UI should render payment test result area');
  assert(html.includes('id="sa-ops-payments"'), 'Superadmin Ops should include dedicated Payments sub-tab');
  assert(html.includes('id="sa-ops-backups"'), 'Superadmin Ops should include dedicated Backups sub-tab');
  assert(html.includes('/admin/webhooks/events'), 'Superadmin UI should fetch webhook timeline endpoint');
  assert(html.includes('retryWebhookUi('), 'Superadmin UI should expose webhook retry action');

  console.log('Superadmin UI integration checks passed');
}

run();
