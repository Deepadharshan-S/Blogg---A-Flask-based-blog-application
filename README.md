# Blogg

A full-featured blogging and social networking web application built with **Flask 3.1**, **SQLAlchemy 2.0**, and managed by **uv**.

Blogg ships with a native IAM layer (no external identity provider): multi-factor authentication, role-based access control with an admin console, audit and access logging, server-side session and API-token management, account lockout, a password policy, and account lifecycle management (forced password change, opt-in password expiry, anonymizing deletion) — all alongside the full blogging feature set.

---

## Features

- **Authentication & Security**:
  - Registration, login, logout, password reset, and email confirmation via signed cryptographic tokens.
  - Rate limiting with Flask-Limiter on login endpoints.
  - Strong password requirements (regex validation) and Werkzeug password hashing.
  - Standard HTTP security headers (`X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`).
- **Multi-Factor Authentication (TOTP)**:
  - RFC 6238 TOTP (pyotp) with QR-code enrolment (`/auth/security/mfa/setup`) for any authenticator app.
  - Single-use backup codes for lockout recovery.
  - MFA challenge step at login (`/auth/mfa`); API clients pass an OTP via the `X-MFA-OTP` header.
  - Disable MFA from the security center, re-authenticating with password + code.
- **Account Lockout & Password Policy**:
  - Temporary lockout after `BLOGG_MAX_FAILED_LOGINS` consecutive failures (`BLOGG_LOCKOUT_MINUTES`).
  - Password history (`BLOGG_PASSWORD_HISTORY_COUNT`) — recent passwords cannot be reused.
  - Password change forces revocation of all *other* sessions.
  - Forced password change: an admin flags an account (console button or `PATCH /admin/users/<id>` with 
`must_change_password`); until a new password is set every page redirects to the change form and API credentials 
answer `403 password change required`.
  - Opt-in password expiry (`BLOGG_PASSWORD_MAX_AGE_DAYS`, off by default): expired passwords are forced through 
the same change flow, and the API answers `403 password expired`.
  - Uniform error messages (no account enumeration on login or password reset).
- **Role-Based Access Control (RBAC) & Admin Console**:
  - Permissions bitmask (`FOLLOW`, `COMMENT`, `WRITE`, `MODERATE`, `ADMIN`, `MANAGE_USERS`, `VIEW_AUDIT`).
  - Roles: `User`, `Moderator`, `Administrator`.
  - Admin console at `/admin`: dashboard, user management (disable/enable, role change, force password reset, revoke sessions), role & permission editor, a filterable audit log, and the per-request access log.
  - Guardrails: the last Administrator cannot be demoted or disabled, and roles with users cannot be deleted; admins cannot change their own role or disable their own account.
- **Audit & Access Logging**:
  - Every security event (login success/failure, lockout, MFA, password/email/role changes, session and token lifecycle, admin actions) recorded in a single `audit_events` stream with IP address and user agent.
  - Audit log viewer at `/admin/audit` with event/actor/result filters; login history is derived from the same stream. Export the (filtered) trail as CSV/JSON, and keep it with a configurable retention window (`flask prune-logs`).
  - Per-request access log (`access_logs`): every HTTP request is recorded with the acting identity (web session or API token), method, path, status, duration, IP and user agent — query strings are never stored and one-time tokens in paths are redacted. View it at `/admin/access-logs`; static assets are excluded.
  - Both trails guard themselves: viewing or exporting either log is itself audited (`audit.viewed`, `audit.exported`, `access_log.viewed`), and pruning writes `logs.pruned`.
- **Session Management**:
  - Server-side sessions (UUID `jti` in the session cookie) with idle and absolute timeouts.
  - Security center (`/auth/security`) lists active devices; revoke any session or all others in one click.
  - Full revocation stamps a per-user cutoff: any identity issued before it (including remember-me cookies) is 
refused at load time.
- **API Tokens**:
  - Opaque 64-hex tokens, stored only as SHA-256 hashes, with explicit scopes (`profile:read`, `posts:read`, `posts:write`, `comments:write`, `tokens:manage`, `admin`) and TTL limits.
  - Self-service management in the security center and via `GET/POST/DELETE /api/v1/tokens`.
  - Legacy signed tokens continue to work with full access (backward compatible).
- **Blogging & Social Network**:
  - Markdown post editor with live preview (Flask-PageDown) and server-side Bleach HTML sanitization.
  - Estimated reading time on every post (e.g. `• 2 min read`).
  - Interactive post likes with AJAX updates.
  - Full-text search for posts and users.
  - Dark mode / light mode toggle with local storage persistence.
  - User profile pages, Gravatar integration, and automatic `last_seen` timestamp tracking.
  - Follow/unfollow users and toggle feeds between "All Posts" and "Followed Users".
- **Comment System & Moderation**:
  - Comment threads on posts.
  - Moderation dashboard allowing moderators and administrators to review and hide/unhide comments.
- **Headless REST API v1 (`/api/v1`)** — see [API Reference](#api-reference-v1).
- **Background Tasks & Observability**:
  - Asynchronous email notifications via background worker threads.
  - Rotating file logging (`logs/blogg.log`).
- **Modern Code Quality Tooling**:
  - Ruff linter & formatter configuration (`flask lint`, `flask lint-fix`).
  - Code coverage reporting (`flask test-cov`).

---

## Getting Started with uv

This project uses [`uv`](https://docs.astral.sh/uv/) for fast, reproducible dependency management and execution.

### 1. Prerequisites

Make sure Python 3.12+ and `uv` are installed on your system:

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Setup Environment

Clone the repository and install all dependencies:

```bash
git clone <repository-url>
cd Blogg

# Install dependencies into virtual environment using uv
uv sync
```

### 3. Configure Environment Variables

Copy the example environment file and customize your settings:

```bash
cp .env.example .env
```

Open `.env` and fill in:
- `FLASK_APP`: Set to `blogg.py` (default).
- `SECRET_KEY`: A strong secret key (generate with `python -c "import secrets; print(secrets.token_hex(16))"`). **Required in production** — the app fails fast at startup if it is missing (development generates an ephemeral key, testing uses a fixed one).
- `MAIL_USERNAME` and `MAIL_PASSWORD`: SMTP credentials for sending verification emails.
- `BLOGG_ADMIN`: Email of the default administrator account.

All IAM settings are optional and default sensibly (see `.env.example` for the full list):

| Variable | Default | Purpose |
| --- | --- | --- |
| `BLOGG_MAX_FAILED_LOGINS` | `5` | Failed logins before temporary lockout |
| `BLOGG_LOCKOUT_MINUTES` | `15` | Lockout duration |
| `BLOGG_SESSION_IDLE_MINUTES` | `60` | Idle session timeout |
| `BLOGG_SESSION_ABSOLUTE_HOURS` | `24` | Absolute session timeout |
| `BLOGG_TOKEN_DEFAULT_TTL` / `BLOGG_TOKEN_MAX_TTL` | `3600` / `2592000` | API token TTL bounds (seconds) |
| `BLOGG_PASSWORD_HISTORY_COUNT` | `5` | Recent passwords that cannot be reused |
| `BLOGG_PASSWORD_MAX_AGE_DAYS` | `0` | Password max age in days (`0` = never expires) |
| `BLOGG_MFA_ISSUER` | `Blogg` | TOTP issuer label in authenticator apps |
| `BLOGG_ENFORCE_MFA_FOR_ADMINS` | `false` | Require MFA for Administrators |
| `BLOGG_LOGIN_RATE_LIMIT` | `5 per minute` | Login/MFA challenge rate limit |
| `RATELIMIT_STORAGE_URI` | `memory://` | Rate-limit storage (`filesystem://` in production) |
| `BLOGG_ACCESS_LOG_ENABLED` | `true` | Record the per-request access trail |
| `BLOGG_ACCESS_LOG_EXCLUDE_PREFIXES` | `/static` | Comma-separated path prefixes never logged |
| `BLOGG_ACCESS_LOG_RETENTION_DAYS` | `0` | Access-record retention for `flask prune-logs` (`0` = keep forever) |
| `BLOGG_AUDIT_RETENTION_DAYS` | `0` | Audit-event retention for `flask prune-logs` (`0` = keep forever) |

### 4. Database Setup & Migrations

Initialize database roles and seed sample data:

```bash
# Apply database migrations and insert default roles
uv run flask init-db

# (Optional) Seed an administrator account
uv run flask seed-admin --email admin@example.com --username admin

# (Optional) Seed sample users and posts
uv run flask seed-data --users 20 --posts 50
```

### 5. Run the Application

Start the Flask development server:

```bash
uv run flask run --debug
```

Or explicitly specify the app:

```bash
uv run flask --app blogg run --debug
```

The application will be accessible at `http://127.0.0.1:5000`.

---

## IAM Usage

### Security Center (self-service)

Every signed-in user has a security center at **`/auth/security`**:

- **Change password** — enforces the password policy and password history; revokes all other sessions on success.
- **Two-factor authentication** — enrol via QR code (`/auth/security/mfa/setup`), verify a TOTP code to activate, and disable with password + code (`/auth/security/mfa/disable`). Single-use backup codes are shown at enrolment.
- **Active sessions** — list every device (created, last seen, IP, user agent), revoke one (`/auth/security/sessions/<jti>/revoke`) or sign out everywhere else (`/auth/security/sessions/revoke-others`).
- **Account deletion** — the danger zone at the bottom tombstones the account (password confirmation required): identity, password and MFA are destroyed, every session and API token is revoked, and posts/comments stay on the site under an anonymous `deleted_<id>` handle. The last Administrator cannot delete themselves.

### Admin Console (`/admin`)

| Route | Permission | Purpose |
| --- | --- | --- |
| `/admin/` | `MANAGE_USERS` | Dashboard with IAM counters and recent security events |
| `/admin/users`, `/admin/users/<id>` | `MANAGE_USERS` | Search users; change role, disable/enable, force password reset, require password change, reset MFA, revoke sessions, delete account (tombstone) |
| `/admin/roles`, `/admin/roles/<id>/edit` | `ADMIN` | Create/edit/delete roles and their permission bitmask |
| `/admin/audit` | `VIEW_AUDIT` | Filterable audit log and login history |
| `/admin/audit/export` | `VIEW_AUDIT` | Download the (filtered) audit trail as CSV or JSON |
| `/admin/access-logs` | `VIEW_AUDIT` | Per-request access trail (identity, path, status, duration, IP) |

Guardrails enforced in both the console and the API: the **last Administrator** cannot be demoted, disabled, deleted, or delete themselves, and **roles with users** cannot be deleted. Deleted accounts become anonymized tombstones (`deleted_<id>`): they keep their authored content, lose every credential, and refuse further admin actions.

### Audit Events

Security-relevant actions are written to the `audit_events` table with event name, actor, target, success flag, detail payload (JSON), IP address, and user agent — e.g. `auth.login.success`, `auth.login.failed`, `auth.login.locked`, `mfa.enabled`, `password.changed`, `session.revoked`, `session.expired`, `token.created`, `user.role_changed`, `user.password_change_required`, `user.deleted`. Log lifecycle is audited too: `audit.viewed`, `audit.exported`, `access_log.viewed`, and `logs.pruned`. The admin audit view and login history both read from this single stream.

### Access Log

Every request (HTML and API) appends one row to `access_logs`: timestamp, acting identity (web session *or* API token — whichever authorized the request), method, sanitized path, Flask endpoint, status code, duration in ms, IP, and user agent. Retention is enforced with `flask prune-logs` once `BLOGG_ACCESS_LOG_RETENTION_DAYS`/`BLOGG_AUDIT_RETENTION_DAYS` are set to a positive number of days.

---

## API Reference (v1)

Base path: `/api/v1` (the API blueprint is CSRF-exempt; use token/credential auth instead).

### Authenticating

Every API client must authenticate. Credentialed requests that fail are **rejected with `401`/`403` even on public endpoints** (no silent downgrade to anonymous).

1. **Bearer token** (recommended):
   ```bash
   # Create a token (Basic auth, or JSON body {"email","password"}); add scope/TTL as needed
   curl -X POST http://127.0.0.1:5000/api/v1/tokens -u EMAIL:PASSWORD \
        -H 'Content-Type: application/json' \
        -d '{"name": "cli", "scopes": ["posts:read", "posts:write"], "expires_in": 3600}'

   curl http://127.0.0.1:5000/api/v1/posts -H 'Authorization: Bearer <token>'
   ```
2. **HTTP Basic**: `-u EMAIL:PASSWORD`.
3. **MFA**: when the account has TOTP enabled, supply the current code via the `X-MFA-OTP` header (or an `otp` JSON field on `POST /tokens`) alongside Basic auth.

### Scopes

| Scope | Grants |
| --- | --- |
| `profile:read` | `GET /me` |
| `posts:read` | Read posts |
| `posts:write` | Create/like/update posts |
| `comments:write` | Create/update/delete comments |
| `tokens:manage` | `GET/POST/DELETE /tokens` (self-service) |
| `admin` | `GET/PATCH/DELETE /admin/*` (admin API) |

New tokens default to every scope **except** `tokens:manage` and `admin`. Legacy signed tokens (issued before the IAM layer) are accepted with full access for backward compatibility. Missing/insufficient scope → `403`.

### Endpoints

| Method & path | Auth | Notes |
| --- | --- | --- |
| `POST /tokens` | Basic or JSON creds (+`X-MFA-OTP`) | Issue a token; returns the secret **once** |
| `GET /tokens` | Bearer + `tokens:manage` | List your tokens (secrets never returned) |
| `DELETE /tokens/<id>` | Bearer + `tokens:manage` | Revoke one of your tokens |
| `GET /me/sessions` | Bearer | List your active login sessions |
| `DELETE /me/sessions`, `DELETE /me/sessions/all` | Bearer | Sign out all *other* sessions / all sessions |
| `GET /me` | Bearer | Profile (`profile:read`) |
| `GET /posts`, `GET /posts/<id>` | Bearer | Read posts (`posts:read`) |
| `POST /posts`, `PUT /posts/<id>`, `POST /posts/<id>/like` | Bearer | Write posts (`posts:write`) |
| `GET /admin/users`, `PATCH /admin/users/<id>`, `DELETE /admin/users/<id>` | Bearer + `admin` | User administration: role/active/confirmed/`must_change_password`, tombstone deletion |
| `GET /admin/roles`, `POST /admin/roles`, ... | Bearer + `admin` | Role administration |
| `GET /admin/audit` | Bearer + `admin` | Audit log query with filters |
| `GET /admin/access-logs` | Bearer + `admin` | Access log query (`?q=`, `?method=`, `?status=2xx`, `?page=`) |

Error responses are JSON (`{"message": "..."}`) with conventional status codes: `400` validation/guard violation, `401` missing or invalid credentials, `403` insufficient permission or scope, `404` not found, `429` rate limited.

---

## Developer Commands & Testing

Run unit tests and linting via custom CLI commands:

```bash
# Run unit test suite
uv run flask test

# Run tests with code coverage report
uv run flask test-cov

# Check linting and formatting
uv run flask lint

# Auto-format and fix lint issues
uv run flask lint-fix

# Delete audit/access records past their configured retention (0 = keep forever)
uv run flask prune-logs
```

---

## Project Structure

```plaintext
Blogg/
├── app/                       # Core application factory & blueprints
│   ├── api/                   # Headless REST API v1 (auth, posts, tokens, admin)
│   ├── auth/                  # Authentication blueprint (login, MFA, security center)
│   ├── admin/                 # Admin console blueprint (users, roles, audit, access logs)
│   ├── main/                  # Core blog features (posts, comments, profiles, search)
│   ├── models.py              # Models (User, Role, Post, ..., AuditEvent, AccessLog, UserSession, ApiToken)
│   ├── security.py            # IAM services (audit/access logs, auth policy, sessions, tokens)
│   ├── decorators.py          # RBAC decorators (permission_required, admin_required, ...)
│   ├── cli.py                 # Factory-registered CLI commands (prune-logs)
│   ├── email.py               # Async email utility
│   ├── fake.py                # Fake data generator
│   ├── static/                # CSS, fonts, and client-side assets
│   └── templates/             # Jinja2 templates (Inter + Dark/Light mode)
├── tests/                     # Unit test suite (baseline blog + IAM)
├── migrations/                # Database migration scripts (Alembic)
├── pyproject.toml             # Project configuration and uv dependencies
├── uv.lock                    # Deterministic dependency lockfile
├── config.py                  # Configuration environments (incl. IAM settings)
├── blogg.py                   # Application entry point & custom CLI commands
├── .env.example               # Template environment configuration
└── .gitignore                 # Git ignore rules
```
