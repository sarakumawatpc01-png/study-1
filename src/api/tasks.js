const express = require('express');
const { z } = require('zod');
const db = require('../db');
const { authRequired } = require('../middleware/auth');

const router = express.Router();
router.use(authRequired);

const createTaskSchema = z.object({
  task_id: z.string().min(1),
  title: z.string().min(1),
  topic: z.string().min(1),
  suggested_time: z.number().int().positive(),
});

const statusSchema = z.enum(['pending', 'in-progress', 'completed', 'skipped', 'interrupted']);

function getTaskByTaskId(userId, taskId) {
  return db.prepare('SELECT * FROM tasks WHERE user_id = ? AND task_id = ?').get(userId, taskId);
}

function addTaskEvent(userId, taskId, eventType, reason = null, actual = null, suggested = null) {
  db.prepare(
    'INSERT INTO task_events (user_id, task_id, event_type, event_reason, actual_time, suggested_time, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(userId, taskId, eventType, reason, actual, suggested, new Date().toISOString());
}

router.get('/', (req, res) => {
  const tasks = db
    .prepare('SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC')
    .all(req.user.id);
  res.json(tasks);
});

router.post('/', (req, res) => {
  const parsed = createTaskSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid task payload' });

  const { task_id, title, topic, suggested_time } = parsed.data;
  const createdAt = new Date().toISOString();
  try {
    db.prepare(
      'INSERT INTO tasks (user_id, task_id, title, topic, status, suggested_time, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(req.user.id, task_id, title, topic, 'pending', suggested_time, createdAt);
  } catch (e) {
    return res.status(409).json({ error: 'Task already exists' });
  }
  res.status(201).json(getTaskByTaskId(req.user.id, task_id));
});

router.post('/:taskId/start', (req, res) => {
  const task = getTaskByTaskId(req.user.id, req.params.taskId);
  if (!task) return res.status(404).json({ error: 'Task not found' });
  if (task.status === 'completed' || task.status === 'skipped') {
    return res.status(400).json({ error: 'Task already finalized' });
  }
  if (task.status === 'in-progress') return res.json(task);

  const startedAt = new Date().toISOString();
  db.prepare(
    'UPDATE tasks SET status = ?, started_at = ?, completed_at = NULL, interruption_flag = 0 WHERE id = ?'
  ).run('in-progress', startedAt, task.id);
  addTaskEvent(req.user.id, task.task_id, 'started', null, null, task.suggested_time);
  res.json(getTaskByTaskId(req.user.id, req.params.taskId));
});

router.post('/:taskId/complete', (req, res) => {
  const schema = z.object({
    actual_time: z.number().int().nonnegative(),
    early_completion_reason: z.string().optional().nullable(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid completion payload' });

  const task = getTaskByTaskId(req.user.id, req.params.taskId);
  if (!task) return res.status(404).json({ error: 'Task not found' });
  if (task.status !== 'in-progress' && task.status !== 'interrupted') {
    return res.status(400).json({ error: 'Task must be in-progress/interrupted to complete' });
  }

  const { actual_time, early_completion_reason } = parsed.data;
  if (actual_time < task.suggested_time && !early_completion_reason) {
    return res.status(400).json({ error: 'early_completion_reason required for early finish' });
  }

  db.prepare(
    'UPDATE tasks SET status=?, actual_time=?, completed_at=?, early_completion_reason=?, skipped_reason=NULL, interruption_flag=0 WHERE id=?'
  ).run(
    'completed',
    actual_time,
    new Date().toISOString(),
    early_completion_reason || null,
    task.id
  );
  addTaskEvent(
    req.user.id,
    task.task_id,
    'completed',
    early_completion_reason || null,
    actual_time,
    task.suggested_time
  );
  res.json(getTaskByTaskId(req.user.id, req.params.taskId));
});

router.post('/:taskId/skip', (req, res) => {
  const schema = z.object({ reason: z.string().min(1) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Skip reason is required' });

  const task = getTaskByTaskId(req.user.id, req.params.taskId);
  if (!task) return res.status(404).json({ error: 'Task not found' });
  if (task.status === 'completed') return res.status(400).json({ error: 'Completed task cannot be skipped' });

  db.prepare(
    'UPDATE tasks SET status=?, skipped_reason=?, completed_at=?, interruption_flag=0 WHERE id=?'
  ).run('skipped', parsed.data.reason, new Date().toISOString(), task.id);
  addTaskEvent(req.user.id, task.task_id, 'skipped', parsed.data.reason, task.actual_time, task.suggested_time);
  res.json(getTaskByTaskId(req.user.id, req.params.taskId));
});

router.post('/:taskId/interrupt', (req, res) => {
  const schema = z.object({ actual_time: z.number().int().nonnegative() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid interruption payload' });

  const task = getTaskByTaskId(req.user.id, req.params.taskId);
  if (!task) return res.status(404).json({ error: 'Task not found' });
  if (task.status !== 'in-progress') return res.status(400).json({ error: 'Only in-progress task can be interrupted' });

  db.prepare('UPDATE tasks SET status=?, actual_time=?, interruption_flag=1 WHERE id=?')
    .run('interrupted', parsed.data.actual_time, task.id);
  addTaskEvent(req.user.id, task.task_id, 'interrupted', 'early_exit', parsed.data.actual_time, task.suggested_time);
  res.json(getTaskByTaskId(req.user.id, req.params.taskId));
});

router.patch('/:taskId/status', (req, res) => {
  const schema = z.object({ status: statusSchema });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid status' });
  const task = getTaskByTaskId(req.user.id, req.params.taskId);
  if (!task) return res.status(404).json({ error: 'Task not found' });

  db.prepare('UPDATE tasks SET status = ? WHERE id = ?').run(parsed.data.status, task.id);
  res.json(getTaskByTaskId(req.user.id, req.params.taskId));
});

module.exports = router;
