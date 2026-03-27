const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const db = require('../db');
const { authRequired } = require('../middleware/auth');

const router = express.Router();
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });

const signupSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().min(2),
  exam: z.string().min(2),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

router.post('/signup', authLimiter, async (req, res) => {
  const parsed = signupSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid input' });

  const { email, password, name, exam } = parsed.data;
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return res.status(409).json({ error: 'Email already exists' });

  const passwordHash = await bcrypt.hash(password, 10);
  const createdAt = new Date().toISOString();

  const tx = db.transaction(() => {
    const result = db
      .prepare(
        'INSERT INTO users (email, password_hash, name, exam, created_at) VALUES (?, ?, ?, ?, ?)'
      )
      .run(email, passwordHash, name, exam, createdAt);
    db.prepare('INSERT INTO profiles (user_id, mood, readiness_score) VALUES (?, ?, ?)')
      .run(result.lastInsertRowid, 'Normal / Okay', 50);
    return result.lastInsertRowid;
  });

  const userId = tx();
  const token = jwt.sign({ userId, email }, process.env.JWT_SECRET, {
    expiresIn: '7d',
  });
  res.status(201).json({ token, user: { id: userId, email, name, exam } });
});

router.post('/login', authLimiter, async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid input' });

  const { email, password } = parsed.data;
  const user = db
    .prepare('SELECT id, email, name, exam, password_hash FROM users WHERE email = ?')
    .get(email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET, {
    expiresIn: '7d',
  });
  res.json({
    token,
    user: { id: user.id, email: user.email, name: user.name, exam: user.exam },
  });
});

router.get('/me', authRequired, (req, res) => {
  const user = db
    .prepare(
      'SELECT u.id, u.email, u.name, u.exam, p.mood, p.readiness_score AS readinessScore FROM users u JOIN profiles p ON p.user_id = u.id WHERE u.id = ?'
    )
    .get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

module.exports = router;
