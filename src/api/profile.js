const express = require('express');
const { z } = require('zod');
const db = require('../db');
const { authRequired } = require('../middleware/auth');

const router = express.Router();
router.use(authRequired);

router.get('/', (req, res) => {
  const profile = db
    .prepare('SELECT mood, readiness_score FROM profiles WHERE user_id = ?')
    .get(req.user.id);
  const moods = db
    .prepare('SELECT mood, note, created_at FROM moods WHERE user_id = ? ORDER BY created_at DESC LIMIT 30')
    .all(req.user.id);
  res.json({ profile, moods });
});

router.post('/mood', (req, res) => {
  const schema = z.object({
    mood: z.string().min(2),
    note: z.string().optional().nullable(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid mood payload' });

  try {
    db.transaction(() => {
      db.prepare('UPDATE profiles SET mood = ? WHERE user_id = ?').run(parsed.data.mood, req.user.id);
      db.prepare('INSERT INTO moods (user_id, mood, note, created_at) VALUES (?, ?, ?, ?)')
        .run(req.user.id, parsed.data.mood, parsed.data.note || null, new Date().toISOString());
    })();
    res.status(201).json({ ok: true });
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('Failed to save mood', e);
    res.status(500).json({ error: 'Failed to save mood' });
  }
});

module.exports = router;
