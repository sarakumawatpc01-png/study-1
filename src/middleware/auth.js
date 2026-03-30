const jwt = require('jsonwebtoken');
const db = require('../db');

function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing auth token' });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = db
      .prepare('SELECT id, email, role, is_active, token_version, mfa_enabled FROM users WHERE id = ?')
      .get(payload.userId);
    if (!user || Number(user.is_active) !== 1) {
      return res.status(401).json({ error: 'User is disabled or not found' });
    }
    if (Number(payload.tokenVersion || 0) !== Number(user.token_version || 0)) {
      return res.status(401).json({ error: 'Session invalidated. Please login again.' });
    }
    req.user = {
      id: user.id,
      email: user.email,
      role: user.role || 'student',
      mfa_enabled: Number(user.mfa_enabled) === 1,
    };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { authRequired };
