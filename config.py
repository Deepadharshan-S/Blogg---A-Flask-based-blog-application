import os
import secrets

from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))


class Config:
    # NOTE: no hardcoded fallback. Production fails fast without SECRET_KEY;
    # development generates an ephemeral key (sessions reset on restart);
    # testing uses a fixed key so signed tokens remain stable per test run.
    SECRET_KEY = os.environ.get("SECRET_KEY")
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.googlemail.com")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "true").lower() in ["true", "on", "1"]
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    BLOGG_MAIL_SUBJECT_PREFIX = "[BLOGG]"
    BLOGG_ADMIN = os.environ.get("BLOGG_ADMIN", "deepadharshan251@gmail.com")
    BLOGG_MAIL_SENDER = os.environ.get("BLOGG_MAIL_SENDER", f"BLOGG Admin <{BLOGG_ADMIN}>")
    BLOGG_POSTS_PER_PAGE = 20
    BLOGG_FOLLOWERS_PER_PAGE = 50
    BLOGG_COMMENTS_PER_PAGE = 30
    RESET_PASSWORD_TOKEN_MAX_AGE = 1800
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    BLOGG_NUM_PROXIES = int(os.environ.get("BLOGG_NUM_PROXIES", "0"))
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_RECORD_QUERIES = True
    BOOTSTRAP_SERVE_LOCAL = True

    # --- IAM settings ---
    BLOGG_MAX_FAILED_LOGINS = int(os.environ.get("BLOGG_MAX_FAILED_LOGINS", "5"))
    BLOGG_LOCKOUT_MINUTES = int(os.environ.get("BLOGG_LOCKOUT_MINUTES", "15"))
    BLOGG_SESSION_IDLE_MINUTES = int(os.environ.get("BLOGG_SESSION_IDLE_MINUTES", "60"))
    BLOGG_SESSION_ABSOLUTE_HOURS = int(os.environ.get("BLOGG_SESSION_ABSOLUTE_HOURS", "24"))
    BLOGG_TOKEN_DEFAULT_TTL = int(os.environ.get("BLOGG_TOKEN_DEFAULT_TTL", "3600"))
    BLOGG_TOKEN_MAX_TTL = int(os.environ.get("BLOGG_TOKEN_MAX_TTL", "2592000"))
    BLOGG_PASSWORD_HISTORY_COUNT = int(os.environ.get("BLOGG_PASSWORD_HISTORY_COUNT", "5"))
    # Maximum password age in days; 0 (default) disables expiry entirely.
    # When enabled, an expired password forces a change at next login.
    BLOGG_PASSWORD_MAX_AGE_DAYS = int(os.environ.get("BLOGG_PASSWORD_MAX_AGE_DAYS", "0"))
    BLOGG_MFA_ISSUER = os.environ.get("BLOGG_MFA_ISSUER", "Blogg")
    BLOGG_ENFORCE_MFA_FOR_ADMINS = os.environ.get(
        "BLOGG_ENFORCE_MFA_FOR_ADMINS", "false"
    ).lower() in ["true", "on", "1"]
    # Rate limit applied to the login and MFA challenge endpoints (callable per-request).
    BLOGG_LOGIN_RATE_LIMIT = os.environ.get("BLOGG_LOGIN_RATE_LIMIT", "5 per minute")
    BLOGG_ADMIN_PER_PAGE = 20
    BLOGG_AUDIT_PER_PAGE = 30
    BLOGG_ACCESS_LOG_PER_PAGE = 30

    # --- Audit & access log settings ---
    # Structured per-request access trail (Admin console -> Access Log).
    BLOGG_ACCESS_LOG_ENABLED = os.environ.get("BLOGG_ACCESS_LOG_ENABLED", "true").lower() in [
        "true",
        "on",
        "1",
    ]
    # Comma-separated path prefixes that are never written to the access log.
    BLOGG_ACCESS_LOG_EXCLUDE_PREFIXES = tuple(
        p.strip()
        for p in os.environ.get("BLOGG_ACCESS_LOG_EXCLUDE_PREFIXES", "/static").split(",")
        if p.strip()
    )
    # Retention windows (days) enforced by `flask prune-logs`; 0 keeps records forever.
    BLOGG_ACCESS_LOG_RETENTION_DAYS = int(os.environ.get("BLOGG_ACCESS_LOG_RETENTION_DAYS", "0"))
    BLOGG_AUDIT_RETENTION_DAYS = int(os.environ.get("BLOGG_AUDIT_RETENTION_DAYS", "0"))

    # Rate limiting: in-memory by default (tests/dev), persistent in production.
    RATELIMIT_STORAGE_URI = "memory://"

    # Cookie hardening: identity cookies are JS-invisible and never sent
    # cross-site without a top-level navigation (mitigates CSRF + theft).
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"

    @classmethod
    def init_app(cls, app):
        if not app.config.get("SECRET_KEY"):
            if app.config.get("TESTING"):
                app.config["SECRET_KEY"] = "blogg-testing-secret-key"
            elif app.config.get("DEBUG"):
                app.config["SECRET_KEY"] = secrets.token_hex(32)
                app.logger.warning(
                    "SECRET_KEY not set - generated an ephemeral development key. "
                    "Sessions and tokens will not survive a restart."
                )
            else:
                raise RuntimeError(
                    "SECRET_KEY environment variable must be set in production. "
                    'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
                )


class DevelopmentConfig(Config):
    DEBUG = True
    TEMPLATES_AUTO_RELOAD = True
    SQLALCHEMY_DATABASE_URI = os.environ.get("DEV_DATABASE_URL") or "sqlite:///" + os.path.join(
        basedir, "data-dev.sqlite"
    )


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get("TEST_DATABASE_URL") or "sqlite://"
    RATELIMIT_STORAGE_URI = "memory://"
    # Tests (e.g. lockout) intentionally exceed the production login limit.
    BLOGG_LOGIN_RATE_LIMIT = "1000 per minute"


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:///" + os.path.join(
        basedir, "data.sqlite"
    )
    RATELIMIT_STORAGE_URI = os.environ.get(
        "RATELIMIT_STORAGE_URI", "filesystem://" + os.path.join(basedir, "logs", "ratelimit")
    )
    # Secure cookies by default in production; set SESSION_COOKIE_SECURE=false
    # (and/or REMEMBER_COOKIE_SECURE=false) when serving plain HTTP behind a
    # trusted proxy during initial rollout.
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "true").lower() in [
        "true",
        "on",
        "1",
    ]
    REMEMBER_COOKIE_SECURE = os.environ.get("REMEMBER_COOKIE_SECURE", "true").lower() in [
        "true",
        "on",
        "1",
    ]

    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        secret_key = os.environ.get("SECRET_KEY")
        if not secret_key:
            raise RuntimeError("SECRET_KEY must be set in production")
        app.config["SECRET_KEY"] = secret_key

        ratelimit_storage = app.config.get("RATELIMIT_STORAGE_URI", "memory://")
        if ratelimit_storage == "memory://":
            app.logger.warning(
                "Production rate limiting is using 'memory://' storage. "
                "For multi-worker deployments, set RATELIMIT_STORAGE_URI to a distributed backend (e.g. redis://host:port/0)."
            )


config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
