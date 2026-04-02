# Production Readiness Guide

## 1) Required environment variables

Create a `.env` file (do not commit it) with at least:

- `NODE_ENV=production`
- `PORT=3000`
- `JWT_SECRET=<long random secret (>=32 chars)>`
- `AUDIT_SIGNING_SECRET=<long random secret (>=32 chars)>`
- `PAYMENT_CONFIG_ENCRYPTION_KEY=<long random secret (>=32 chars)>`
- `CORS_ALLOWED_ORIGINS=https://study.<yourdomain>,https://www.study.<yourdomain>`

Recommended:

- `TRUST_PROXY=true` (required behind Nginx Proxy Manager)
- `JSON_BODY_LIMIT=1mb`
- `ADMIN_REQUIRE_MFA=true`
- `ADMIN_IP_ALLOWLIST=<comma separated IPs>` (optional)
- `DATA_ROOT_DIR=/app`

Security guidance:

- Use unique, high-entropy secrets for all secret variables.
- Rotate secrets periodically and immediately on suspected exposure.
- Never commit `.env` or plaintext secrets to git.

## 2) Run locally with Docker

```bash
docker compose up --build -d
docker compose logs -f study
curl http://127.0.0.1:3000/health
```

Stop:

```bash
docker compose down
```

## 3) Deploy on VPS with Nginx Proxy Manager (NPM)

1. Copy repository to VPS.
2. Create production `.env` in repo root.
3. Start app:

```bash
docker compose up --build -d
```

4. In Nginx Proxy Manager, create Proxy Host:
   - **Domain Names:** `study.<mydomain>`
   - **Scheme:** `http`
   - **Forward Hostname / IP:** `127.0.0.1`
   - **Forward Port:** `3000`
   - **Block Common Exploits:** enabled
   - **Websockets Support:** enabled
5. In SSL tab, request Let’s Encrypt certificate and force SSL.

Public entrypoint remains only NPM on ports 80/443.

## 4) Data persistence and backups (SQLite)

SQLite file is persisted in Docker volume `study_data` at `/app/data/app.db`.

### Quick backup (volume tar)

```bash
docker run --rm -v study_study_data:/from -v "$PWD":/to alpine sh -c "cd /from && tar -czf /to/study_data_backup_$(date +%F).tar.gz ."
```

### File-level backup (optional daily cron)

```bash
docker compose exec -T study sh -lc 'cp /app/data/app.db /app/data/app.db.bak'
```

Then copy backup off-server (object storage/remote host).

## 5) Upgrade checklist

1. Backup DB volume (`study_data`) first.
2. Pull latest code.
3. Review `.env` for newly required vars.
4. Rebuild and restart:

```bash
docker compose up --build -d
```

5. Verify health:

```bash
curl -fsS http://127.0.0.1:3000/health
```

6. Verify login/signup and key admin routes.
7. Keep old image available for quick rollback.

## 6) Operational notes

- CORS is allowlist-driven in production via `CORS_ALLOWED_ORIGINS`.
- Auth endpoints (`/api/auth/login`, `/api/auth/signup`) are strictly rate limited.
- Helmet CSP is enabled; `unsafe-inline` remains for current static UI compatibility.
- App supports graceful shutdown on `SIGTERM`/`SIGINT` for Docker stop/restart.
- Request logging omits query strings to reduce secret/token leakage risk.
