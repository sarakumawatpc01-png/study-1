const express = require('express');
const { z } = require('zod');
const db = require('../db');
const { authRequired } = require('../middleware/auth');

const router = express.Router();
router.use(authRequired);

function adminRequired(req, res, next) {
  const configuredAdmin = String(process.env.SUPERADMIN_EMAIL || '').trim().toLowerCase();
  if (!configuredAdmin) return next();
  if (String(req.user.email || '').toLowerCase() !== configuredAdmin) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  return next();
}

// Lightweight rule-based quick triage for question reports so admins get an immediate likely bug signal.
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

function parseJsonSafe(raw) {
  try {
    return JSON.parse(raw || '{}');
  } catch (_err) {
    return {};
  }
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
      .run(req.user.id, parsed.data.title, parsed.data.body, new Date().toISOString());
    res.status(201).json({ ok: true });
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('Failed to save notification', e);
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
      .run(req.user.id, parsed.data.name, parsed.data.score, parsed.data.total, new Date().toISOString());
    res.status(201).json({ ok: true });
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('Failed to save mock test', e);
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
    ).run(req.user.id, p.topic, p.question, p.your_answer || null, p.correct_answer, p.explanation, p.next_review_at || null, new Date().toISOString());
    res.status(201).json({ ok: true });
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('Failed to save error-journal entry', e);
    res.status(500).json({ error: 'Failed to save error-journal entry' });
  }
});

router.post('/reports', (req, res) => {
  const schema = z.object({
    category: z.enum(['question', 'content', 'technical', 'billing', 'general']).optional(),
    title: z.string().min(3).max(120),
    description: z.string().min(8).max(2000),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid report payload' });
  const now = new Date().toISOString();
  const isQuestion = (parsed.data.category || 'general') === 'question';
  const triage = isQuestion ? inferQuestionBug(parsed.data.description, parsed.data.title) : null;
  const row = db.prepare(
    `INSERT INTO reports
     (user_id, category, title, description, ai_triage_status, ai_triage_summary, ai_triage_bug, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    req.user.id,
    parsed.data.category || 'general',
    parsed.data.title,
    parsed.data.description,
    isQuestion ? 'completed' : 'not_applicable',
    triage ? triage.summary : null,
    triage ? triage.bug : null,
    'open',
    now,
    now
  );
  res.status(201).json({
    ok: true,
    id: row.lastInsertRowid,
    ai_triage: triage ? { status: 'completed', summary: triage.summary, bug: triage.bug } : null,
  });
});

router.get('/reports', (req, res) => {
  const mine = db
    .prepare(
      'SELECT id, category, title, description, status, action_taken, admin_note, created_at, updated_at FROM reports WHERE user_id = ? ORDER BY created_at DESC'
    )
    .all(req.user.id);
  res.json(mine);
});

router.get('/admin/reports', adminRequired, (req, res) => {
  const rows = db
    .prepare(
      `SELECT r.id, r.user_id, u.email, u.name, r.category, r.title, r.description, r.ai_triage_status, r.ai_triage_summary, r.ai_triage_bug, r.status, r.action_taken, r.admin_note, r.created_at, r.updated_at
       FROM reports r
       JOIN users u ON u.id = r.user_id
       ORDER BY r.created_at DESC`
    )
    .all();
  res.json(rows);
});

router.post('/admin/reports/:id/action', adminRequired, (req, res) => {
  const schema = z.object({
    status: z.enum(['open', 'in_review', 'resolved', 'closed']),
    action_taken: z.string().min(2).max(500),
    admin_note: z.string().max(1000).optional().nullable(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid admin action payload' });
  const existing = db.prepare('SELECT id FROM reports WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Report not found' });
  db.prepare('UPDATE reports SET status = ?, action_taken = ?, admin_note = ?, updated_at = ? WHERE id = ?')
    .run(
      parsed.data.status,
      parsed.data.action_taken,
      parsed.data.admin_note || null,
      new Date().toISOString(),
      req.params.id
    );
  res.json({ ok: true });
});

router.get('/admin/content', adminRequired, (_req, res) => {
  const rows = db
    .prepare(
      'SELECT id, course_key, content_type, title, description, data_json, status, updated_by, created_at, updated_at FROM content_library ORDER BY updated_at DESC'
    )
    .all();
  res.json(rows.map((r) => ({ ...r, data: parseJsonSafe(r.data_json) })));
});

router.post('/admin/content', adminRequired, (req, res) => {
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
  const now = new Date().toISOString();
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
  res.status(201).json({ ok: true, id: row.lastInsertRowid });
});

router.post('/admin/content/:id', adminRequired, (req, res) => {
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
  db.prepare(
    'UPDATE content_library SET course_key = ?, title = ?, description = ?, data_json = ?, status = ?, updated_by = ?, updated_at = ? WHERE id = ?'
  ).run(
    parsed.data.course_key || existing.course_key || '',
    parsed.data.title || existing.title,
    parsed.data.description !== undefined ? parsed.data.description : existing.description,
    dataJson,
    parsed.data.status || existing.status,
    req.user.id,
    new Date().toISOString(),
    req.params.id
  );
  res.json({ ok: true });
});

module.exports = router;
