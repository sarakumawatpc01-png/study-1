# study

Production-ready full-stack implementation for the EXAMBHAI plan.

## Stack
- Frontend: Static HTML/CSS/JS (`public/index.html`) integrated with APIs
- Backend: Node.js + Express
- Database: SQLite (`better-sqlite3`) in `data/app.db`
- Auth: JWT (signup/login)

## Features implemented
- JWT authentication (signup/login/me)
- User profile + mood logs
- Planner/task engine with strict task schema:
  - `task_id`, `user_id`, `status`, `suggested_time`, `actual_time`, `started_at`, `completed_at`, `skipped_reason`, `early_completion_reason`, `interruption_flag`
- Task transitions:
  - `pending -> in-progress -> completed|skipped|interrupted`
- Full-screen focus mode with stopwatch
- Timer persistence across refresh/navigation
- Early completion mandatory reason capture
- Skip mandatory reason capture
- Interruption handling on early exit / unload
- Analytics API:
  - completion rate, skip frequency/reasons, early completion frequency, time vs suggested, interrupted sessions, behavioral insights
- Notifications, mock test records, error journal APIs
- Input validation and secured APIs

## Setup
1. Install dependencies:
   ```bash
   npm install
   ```
2. Create env file:
   ```bash
   cp .env.example .env
   ```
3. Update `.env` with a strong `JWT_SECRET`.

## Run
- Development:
  ```bash
  npm run dev
  ```
- Production:
  ```bash
  npm start
  ```

Open: `http://localhost:3000`

## Verify
- Run smoke test:
  ```bash
  npm test
  ```

## API overview
- `POST /api/auth/signup`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/tasks`
- `POST /api/tasks`
- `POST /api/tasks/:taskId/start`
- `POST /api/tasks/:taskId/complete`
- `POST /api/tasks/:taskId/skip`
- `POST /api/tasks/:taskId/interrupt`
- `GET /api/analytics/summary`
- `GET /api/profile`
- `POST /api/profile/mood`
- `GET /api/notifications`
- `POST /api/notifications`
- `GET /api/mock-tests`
- `POST /api/mock-tests`
- `GET /api/error-journal`
- `POST /api/error-journal`
