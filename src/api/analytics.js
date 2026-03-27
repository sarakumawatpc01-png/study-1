const express = require('express');
const db = require('../db');
const { authRequired } = require('../middleware/auth');
const { summarizeEvents } = require('../services/analytics');

const router = express.Router();
router.use(authRequired);

router.get('/summary', (req, res) => {
  const rows = db
    .prepare(
      'SELECT event_type, event_reason, actual_time, suggested_time, created_at FROM task_events WHERE user_id = ? ORDER BY created_at DESC'
    )
    .all(req.user.id)
    .map((r) => ({
      event_type: r.event_type,
      event_reason: r.event_reason,
      actual_time: r.actual_time == null ? null : Number(r.actual_time),
      suggested_time: r.suggested_time == null ? null : Number(r.suggested_time),
      created_at: r.created_at,
    }));

  const daily = summarizeEvents(
    rows.filter((r) => Date.now() - Date.parse(r.created_at) <= 24 * 60 * 60 * 1000)
  );
  const weekly = summarizeEvents(
    rows.filter((r) => Date.now() - Date.parse(r.created_at) <= 7 * 24 * 60 * 60 * 1000)
  );
  res.json({ daily, weekly });
});

module.exports = router;
