const express = require('express');
const { z } = require('zod');
const db = require('../db');
const { authRequired } = require('../middleware/auth');

const router = express.Router();
router.use(authRequired);

const onboardingSchema = z.object({
  target_exam: z.string().min(2).max(120),
  target_score: z.number().int().min(1).max(1000),
  daily_study_hours: z.number().min(0.5).max(16),
  preparation_level: z.enum(['Beginner', 'Intermediate', 'Advanced']),
  initial_mood_assessment: z.string().min(2).max(120),
});

function nowIso() {
  return new Date().toISOString();
}

function firstWeekTemplate(exam, dailyHours) {
  const topicsByExam = {
    'ssc cgl': ['Quant Fundamentals', 'Reasoning Core', 'English Grammar', 'General Awareness'],
    'ssc chsl': ['Basic Quant', 'Reasoning Basics', 'English Vocabulary', 'Current Affairs'],
    upsc: ['Polity Basics', 'Economy Basics', 'History Revision', 'CSAT Practice'],
  };
  const key = String(exam || '').trim().toLowerCase();
  const topics = topicsByExam[key] || ['Core Concepts', 'Practice MCQs', 'Revision', 'Mock Drill'];
  const minutes = Math.max(30, Math.round(Number(dailyHours || 2) * 60));
  const split = [Math.round(minutes * 0.4), Math.round(minutes * 0.4), Math.max(20, Math.round(minutes * 0.2))];
  const plans = [];
  for (let day = 1; day <= 7; day += 1) {
    plans.push({
      day,
      entries: [
        { title: `${topics[(day - 1) % topics.length]} Study Block`, topic: topics[(day - 1) % topics.length], suggested_time: split[0] },
        { title: `${topics[day % topics.length]} Practice Set`, topic: topics[day % topics.length], suggested_time: split[1] },
        { title: 'Daily Revision + Reflection', topic: 'Revision', suggested_time: split[2] },
      ],
    });
  }
  return plans;
}

function insertOnboardingPlanTasks(userId, exam, dailyStudyHours) {
  const now = nowIso();
  const plans = firstWeekTemplate(exam, dailyStudyHours);
  const upsert = db.prepare(
    'INSERT OR REPLACE INTO tasks (user_id, task_id, title, topic, status, suggested_time, actual_time, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)'
  );
  const tx = db.transaction(() => {
    for (const dayPlan of plans) {
      dayPlan.entries.forEach((entry, index) => {
        upsert.run(
          userId,
          `ONB-W1-D${dayPlan.day}-${index + 1}`,
          entry.title,
          entry.topic,
          'pending',
          entry.suggested_time,
          now
        );
      });
    }
  });
  tx();
  return plans.reduce((sum, d) => sum + d.entries.length, 0);
}

router.get('/status', (req, res) => {
  const row = db.prepare(
    'SELECT u.id, u.onboarding_completed, p.onboarding_data_json FROM users u LEFT JOIN profiles p ON p.user_id = u.id WHERE u.id = ?'
  ).get(req.user.id);
  if (!row) return res.status(404).json({ error: 'User not found' });
  let onboardingData = {};
  try {
    onboardingData = JSON.parse(row.onboarding_data_json || '{}');
  } catch (_err) {
    onboardingData = {};
  }
  return res.json({
    user_id: row.id,
    onboarding_completed: Number(row.onboarding_completed) === 1,
    onboarding_data: onboardingData,
  });
});

router.post('/complete', (req, res) => {
  const parsed = onboardingSchema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ error: 'Invalid onboarding payload' });

  const payload = parsed.data;
  const now = nowIso();
  const createdTaskCount = db.transaction(() => {
    db.prepare('UPDATE users SET exam = ?, onboarding_completed = 1 WHERE id = ?')
      .run(payload.target_exam, req.user.id);
    db.prepare(
      `INSERT INTO profiles (user_id, mood, readiness_score, onboarding_data_json)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET mood = excluded.mood, onboarding_data_json = excluded.onboarding_data_json`
    ).run(
      req.user.id,
      payload.initial_mood_assessment,
      50,
      JSON.stringify({ ...payload, completed_at: now })
    );
    return insertOnboardingPlanTasks(req.user.id, payload.target_exam, payload.daily_study_hours);
  })();

  return res.json({ ok: true, onboarding_completed: true, tasks_created: createdTaskCount });
});

module.exports = router;
