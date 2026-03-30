const crypto = require('crypto');
const db = require('../db');

function parseJsonSafe(raw, fallback) {
  try {
    return JSON.parse(raw || '');
  } catch (_err) {
    return fallback;
  }
}

function getRolePermissions(role) {
  if (!role) return [];
  const row = db.prepare('SELECT permissions_json FROM role_permissions WHERE role = ?').get(role);
  return parseJsonSafe(row?.permissions_json, []);
}

function hasPermission(user, permission) {
  if (!user?.role) return false;
  const permissions = getRolePermissions(user.role);
  return permissions.includes('*') || permissions.includes(permission);
}

function isIpAllowed(req) {
  const configured = String(process.env.ADMIN_IP_ALLOWLIST || '').trim();
  if (!configured) return true;
  const allowlist = configured
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);
  const ip = String(req.ip || req.socket?.remoteAddress || '').trim();
  return allowlist.includes(ip);
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    if (!isIpAllowed(req)) return res.status(403).json({ error: 'IP not allowlisted for admin access' });
    const requireMfa = String(process.env.ADMIN_REQUIRE_MFA || 'true').toLowerCase() !== 'false';
    if (requireMfa && ['superadmin', 'admin', 'support', 'content'].includes(req.user.role) && !req.user.mfa_enabled) {
      return res.status(403).json({ error: 'MFA is mandatory for admin access' });
    }
    if (!hasPermission(req.user, permission)) {
      return res.status(403).json({ error: `Missing permission: ${permission}` });
    }
    return next();
  };
}

function createAuditLog({ actor, action, targetType, targetId, details }) {
  const now = new Date().toISOString();
  const last = db.prepare('SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1').get();
  const prevHash = last?.hash || null;
  const payload = JSON.stringify({
    actor_user_id: actor?.id || null,
    actor_email: actor?.email || null,
    action,
    target_type: targetType,
    target_id: targetId == null ? null : String(targetId),
    details_json: JSON.stringify(details || {}),
    created_at: now,
    prev_hash: prevHash,
  });
  const hash = crypto.createHash('sha256').update(payload).digest('hex');
  const secret = process.env.AUDIT_SIGNING_SECRET || process.env.JWT_SECRET || 'audit-secret';
  const signature = crypto.createHmac('sha256', secret).update(hash).digest('hex');
  db.prepare(
    `INSERT INTO audit_log (actor_user_id, actor_email, action, target_type, target_id, details_json, created_at, prev_hash, hash, signature)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    actor?.id || null,
    actor?.email || null,
    action,
    targetType,
    targetId == null ? null : String(targetId),
    JSON.stringify(details || {}),
    now,
    prevHash,
    hash,
    signature
  );
  return { hash, signature };
}

function requireElevatedAccess(req, res, next) {
  const token = String(req.headers['x-elevated-token'] || '').trim();
  if (!token) return res.status(403).json({ error: 'Elevated access token required' });
  const row = db
    .prepare('SELECT id, expires_at, used_at FROM elevated_access_requests WHERE actor_user_id = ? AND token = ?')
    .get(req.user.id, token);
  if (!row) return res.status(403).json({ error: 'Invalid elevated access token' });
  if (row.used_at) return res.status(403).json({ error: 'Elevated access token already used' });
  if (Date.parse(row.expires_at) <= Date.now()) return res.status(403).json({ error: 'Elevated access token expired' });
  db.prepare('UPDATE elevated_access_requests SET used_at = ? WHERE id = ?').run(new Date().toISOString(), row.id);
  return next();
}

function requireDualApproval(action) {
  return (req, res, next) => {
    const id = Number(req.headers['x-dual-approval-id'] || 0);
    if (!id) return res.status(403).json({ error: 'Dual approval required' });
    const row = db
      .prepare('SELECT status, action FROM dual_approval_requests WHERE id = ?')
      .get(id);
    if (!row || row.status !== 'approved' || row.action !== action) {
      return res.status(403).json({ error: 'Missing approved dual-approval request' });
    }
    return next();
  };
}

module.exports = {
  parseJsonSafe,
  getRolePermissions,
  hasPermission,
  requirePermission,
  createAuditLog,
  requireElevatedAccess,
  requireDualApproval,
};

