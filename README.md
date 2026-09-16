# Blogg

A full-featured blogging and social networking web application built with **Flask 3.1**, **SQLAlchemy 2.0**, and managed by **uv**.

---

## Features

- **Authentication & Security**:
  - Registration, login, logout, password reset, and email confirmation via signed cryptographic tokens.
  - Rate limiting with Flask-Limiter on login endpoints.
  - Strong password requirements (regex validation) and Werkzeug password hashing.
  - Standard HTTP security headers (`X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`).
- **Role-Based Access Control (RBAC)**:
  - Permissions bitmask (`FOLLOW`, `COMMENT`, `WRITE`, `MODERATE`, `ADMIN`).
  - Roles: `User`, `Moderator`, `Administrator`.
  - Decorated endpoints using `@permission_required` and `@admin_required`.
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
- **Headless REST API v1 (`/api/v1`)**:
  - Token-based authentication (`POST /api/v1/tokens`).
  - JSON endpoints for posts, comments, profiles, and post likes.
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
cd blogg

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
- `SECRET_KEY`: A strong secret key (generate with `python -c "import secrets; print(secrets.token_hex(16))"`).
- `MAIL_USERNAME` and `MAIL_PASSWORD`: SMTP credentials for sending verification emails.
- `BLOGG_ADMIN`: Email of the default administrator account.

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
```

---

## Project Structure

```plaintext
blogg/
├── app/                       # Core application factory & blueprints
│   ├── api/                   # Headless REST API v1 endpoints
│   ├── auth/                  # Authentication blueprint (routes, forms)
│   ├── main/                  # Core blog features (posts, comments, profiles, search)
│   ├── models.py              # Database models (User, Role, Post, Comment, Follow, PostLike)
│   ├── decorators.py          # RBAC decorators
│   ├── email.py               # Async email utility
│   ├── fake.py                # Fake data generator
│   ├── static/                # CSS, fonts, and client-side assets
│   └── templates/             # Jinja2 templates (Inter + Dark/Light mode)
├── tests/                     # Unit test suite (basic, user model, API)
├── migrations/                # Database migration scripts (Alembic)
├── pyproject.toml             # Project configuration and uv dependencies
├── uv.lock                    # Deterministic dependency lockfile
├── config.py                  # Configuration environments
├── blogg.py                   # Application entry point & custom CLI commands
├── .env.example               # Template environment configuration
└── .gitignore                 # Git ignore rules
```
