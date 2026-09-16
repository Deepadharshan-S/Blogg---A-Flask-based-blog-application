# Blogg (Flasky)

A full-featured blogging and social networking web application built with **Flask 3.1**, **SQLAlchemy 2.0**, and managed by **uv**.

---

## Features

- **Authentication & Security**:
  - Registration, login, logout, password reset, and email confirmation via signed cryptographic tokens.
  - Rate limiting with Flask-Limiter on login endpoints.
  - Strong password requirements (regex validation) and Werkzeug password hashing.
- **Role-Based Access Control (RBAC)**:
  - Permissions bitmask (`FOLLOW`, `COMMENT`, `WRITE`, `MODERATE`, `ADMIN`).
  - Roles: `User`, `Moderator`, `Administrator`.
  - Decorated endpoints using `@permission_required` and `@admin_required`.
- **Blogging & Social Network**:
  - Markdown post editor with live preview (Flask-PageDown) and server-side Bleach HTML sanitization.
  - User profile pages, Gravatar integration, and automatic `last_seen` timestamp tracking.
  - Follow/unfollow users and toggle feeds between "All Posts" and "Followed Users".
- **Comment System & Moderation**:
  - Comment threads on posts.
  - Moderation dashboard allowing moderators and administrators to review and hide/unhide comments.
- **Background Tasks & Observability**:
  - Asynchronous email notifications via background worker threads.
  - Rotating file logging (`logs/blogg.log`).

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
cd flasky

# Install dependencies into virtual environment using uv
uv sync
```

### 3. Configure Environment Variables

Copy the example environment file and customize your settings:

```bash
cp .env.example .env
```

Open `.env` and fill in:
- `SECRET_KEY`: A strong secret key (generate with `python -c "import secrets; print(secrets.token_hex(16))"`).
- `MAIL_USERNAME` and `MAIL_PASSWORD`: SMTP credentials for sending verification emails.
- `BLOGG_ADMIN`: Email of the default administrator account.

### 4. Database Setup & Migrations

Initialize database roles and seed sample data:

```bash
# Apply database migrations
uv run flask db upgrade

# (Optional) Seed roles and initial fake data via Flask shell
uv run flask shell
>>> from app.models import Role
>>> Role.insert_roles()
>>> from app import fake
>>> fake.users(10)
>>> fake.posts(20)
>>> exit()
```

### 5. Run the Application

Start the Flask development server:

```bash
uv run flask --app flasky run
```

The application will be accessible at `http://127.0.0.1:5000`.

---

## Running Tests

Run the test suite using `uv`:

```bash
uv run python -m unittest discover -s tests
```

Or using `pytest`:

```bash
uv run pytest
```

---

## Project Structure

```plaintext
flasky/
├── app/                       # Core application factory & blueprints
│   ├── auth/                  # Authentication blueprint (routes, forms)
│   ├── main/                  # Core blog features (posts, comments, profiles)
│   ├── models.py              # Database models (User, Role, Post, Comment, Follow)
│   ├── decorators.py          # RBAC decorators
│   ├── email.py               # Async email utility
│   ├── fake.py                # Fake data generator
│   └── templates/             # Jinja2 templates (Bootstrap)
├── tests/                     # Unit test suite
├── migrations/                # Database migration scripts (Alembic)
├── pyproject.toml             # Project configuration and uv dependencies
├── uv.lock                    # Deterministic dependency lockfile
├── config.py                  # Configuration environments
├── flasky.py                  # Application entry point & shell context
├── .env.example               # Template environment configuration
└── .gitignore                 # Git ignore rules
```
