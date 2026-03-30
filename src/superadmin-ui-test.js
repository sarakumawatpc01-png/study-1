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
  assert(html.includes('/admin/payments/rotate'), 'Superadmin UI should expose payment rotate endpoint');
  assert(html.includes('/admin/payments/rollback'), 'Superadmin UI should expose payment rollback endpoint');
  assert(html.includes('/admin/payments/webhooks/validate'), 'Superadmin UI should expose webhook signature validation');
  assert(html.includes('/ingest/payments/webhooks/validate'), 'Superadmin UI should include public ingest webhook validator path');
  assert(html.includes("id=\"sa-pay-test-result\""), 'Superadmin UI should render payment test result area');
  assert(html.includes("id=\"sa-pay-settings-warning\""), 'Superadmin UI should include payment permission-disabled warning');
  assert(html.includes('id="sa-ops-payments"'), 'Superadmin Ops should include dedicated Payments sub-tab');
  assert(html.includes('id="sa-ops-backups"'), 'Superadmin Ops should include dedicated Backups sub-tab');
  assert(html.includes('/admin/webhooks/events'), 'Superadmin UI should fetch webhook timeline endpoint');
  assert(html.includes('retryWebhookUi('), 'Superadmin UI should expose webhook retry action');
  assert(html.includes('/admin/ai/mistral-ocr'), 'Superadmin UI should expose Mistral OCR config endpoint');
  assert(html.includes('/admin/ai/providers'), 'Superadmin UI should expose multi-provider AI config endpoint');
  assert(html.includes('saveAiProviderUi('), 'Superadmin UI should expose save action for AI providers');
  assert(html.includes('openrouter'), 'Superadmin AI UI should include OpenRouter provider');
  assert(html.includes('deepseek'), 'Superadmin AI UI should include DeepSeek provider');
  assert(html.includes('sarvam'), 'Superadmin AI UI should include Sarvam provider');
  assert(html.includes('/admin/content/upload-ocr'), 'Superadmin UI should expose OCR content upload endpoint');

  console.log('Superadmin UI integration checks passed');
}

run();
