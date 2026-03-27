const express = require('express');
const { z } = require('zod');
const db = require('../db');
const { authRequired } = require('../middleware/auth');

const router = express.Router();
router.use(authRequired);

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
  db.prepare('INSERT INTO notifications (user_id, title, body, created_at) VALUES (?, ?, ?, ?)')
    .run(req.user.id, parsed.data.title, parsed.data.body, new Date().toISOString());
  res.status(201).json({ ok: true });
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
  db.prepare('INSERT INTO mock_tests (user_id, name, score, total, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(req.user.id, parsed.data.name, parsed.data.score, parsed.data.total, new Date().toISOString());
  res.status(201).json({ ok: true });
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
  db.prepare(
    'INSERT INTO error_journal (user_id, topic, question, your_answer, correct_answer, explanation, next_review_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(req.user.id, p.topic, p.question, p.your_answer || null, p.correct_answer, p.explanation, p.next_review_at || null, new Date().toISOString());
  res.status(201).json({ ok: true });
});

module.exports = router;
