import os
import secrets
from urllib.parse import urlsplit, urlunsplit

from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))


def sanitize_redis_uri(uri: str) -> str:
    """Redact password from redis://[:password@]host[:port]/db for safe logging."""
    if not uri or "@" not in uri:
        return uri
    try:
        parts = urlsplit(uri)
        if parts.password:
            netloc = parts.netloc.replace(f":{parts.password}@", ":***@")
            return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except Exception:
        pass
    return uri


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
    BLOGG_ADMIN = os.environ.get("BLOGG_ADMIN", "admin@example.com")
    BLOGG_MAIL_SENDER = os.environ.get("BLOGG_MAIL_SENDER", f"BLOGG Admin <{BLOGG_ADMIN}>")
    BLOGG_POSTS_PER_PAGE = 20
    BLOGG_FOLLOWERS_PER_PAGE = 50
    BLOGG_COMMENTS_PER_PAGE = 30
    RESET_PASSWORD_TOKEN_MAX_AGE = 1800
    # Rate Limiting (BLOGG-SEC-017)
    # Storage URI: memory:// (dev/test) or redis://[:password@]host[:port][/db] (production)
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_SWALLOW_ERRORS = os.environ.get("RATELIMIT_SWALLOW_ERRORS", "true").lower() in [
        "true",
        "on",
        "1",
    ]
    RATELIMIT_IN_MEMORY_FALLBACK_ENABLED = os.environ.get(
        "RATELIMIT_IN_MEMORY_FALLBACK_ENABLED", "true"
    ).lower() in ["true", "on", "1"]
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
    # Duration in seconds that an administrator step-up verification remains valid
    BLOGG_ADMIN_STEP_UP_TIMEOUT = int(os.environ.get("BLOGG_ADMIN_STEP_UP_TIMEOUT", "300"))

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

    # MFA Secret Encryption (BLOGG-SEC-015): Dedicated Fernet key(s)
    BLOGG_MFA_ENCRYPTION_KEY = os.environ.get("BLOGG_MFA_ENCRYPTION_KEY")

    # Bounded Email Processing (BLOGG-SEC-016)
    BLOGG_EMAIL_MAX_WORKERS = int(os.environ.get("BLOGG_EMAIL_MAX_WORKERS", "4"))
    BLOGG_EMAIL_QUEUE_CAPACITY = int(os.environ.get("BLOGG_EMAIL_QUEUE_CAPACITY", "50"))

    # Cookie hardening: identity cookies are JS-invisible and never sent
    # cross-site without a top-level navigation (mitigates CSRF + theft).
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"

    @classmethod
    def init_app(cls, app):
        secret_key = os.environ.get("SECRET_KEY") or app.config.get("SECRET_KEY")
        if secret_key:
            app.config["SECRET_KEY"] = secret_key
        elif app.config.get("TESTING"):
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

        # Authenticated encryption key for TOTP secrets at rest (BLOGG-SEC-015)
        mfa_key = os.environ.get("BLOGG_MFA_ENCRYPTION_KEY") or app.config.get(
            "BLOGG_MFA_ENCRYPTION_KEY"
        )
        active_secret = app.config.get("SECRET_KEY")

        if mfa_key and active_secret and mfa_key == active_secret:
            raise RuntimeError(
                "BLOGG_MFA_ENCRYPTION_KEY must NOT be identical to SECRET_KEY. "
                "Use a distinct 32-byte Fernet key for MFA secret encryption."
            )

        if mfa_key:
            app.config["BLOGG_MFA_ENCRYPTION_KEY"] = mfa_key
        elif app.config.get("TESTING"):
            app.config["BLOGG_MFA_ENCRYPTION_KEY"] = "YmxvZ2ctdGVzdC1tZmEtZW5jcnlwdGlvbi1rZXktMzI="
        elif app.config.get("DEBUG"):
            from cryptography.fernet import Fernet

            # SEC-ASSESS-002: Avoid generating a new ephemeral key on every restart
            # when persistent dev database data is used. Check for a persistent key file
            # in the gitignored instance directory.
            dev_key_file = os.path.join(app.instance_path, ".dev_mfa_key")
            loaded_key = None
            if os.path.isfile(dev_key_file):
                try:
                    with open(dev_key_file, "r") as f:
                        candidate = f.read().strip()
                    Fernet(candidate.encode())
                    loaded_key = candidate
                    app.logger.info(
                        "Loaded persistent development MFA encryption key from instance/.dev_mfa_key."
                    )
                except Exception:
                    loaded_key = None

            if not loaded_key:
                new_key = Fernet.generate_key().decode()
                try:
                    os.makedirs(app.instance_path, exist_ok=True)
                    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                    mode = 0o600
                    with open(os.open(dev_key_file, flags, mode), "w") as f:
                        f.write(new_key)
                    loaded_key = new_key
                    app.logger.info(
                        "BLOGG_MFA_ENCRYPTION_KEY not set - generated and saved persistent dev key to instance/.dev_mfa_key."
                    )
                except OSError as e:
                    loaded_key = new_key
                    app.logger.warning(
                        f"BLOGG_MFA_ENCRYPTION_KEY not set - generated ephemeral development key (failed to write {dev_key_file}: {e}). "
                        "Existing encrypted MFA secrets will not decrypt across restarts."
                    )

            app.config["BLOGG_MFA_ENCRYPTION_KEY"] = loaded_key
        else:
            raise RuntimeError(
                "BLOGG_MFA_ENCRYPTION_KEY environment variable must be set in production. "
                'Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
            )

        # Rate Limiting storage backend override (BLOGG-SEC-017)
        if "RATELIMIT_STORAGE_URI" in os.environ:
            app.config["RATELIMIT_STORAGE_URI"] = os.environ["RATELIMIT_STORAGE_URI"]
        if "RATELIMIT_SWALLOW_ERRORS" in os.environ:
            app.config["RATELIMIT_SWALLOW_ERRORS"] = os.environ[
                "RATELIMIT_SWALLOW_ERRORS"
            ].lower() in [
                "true",
                "on",
                "1",
            ]
        if "RATELIMIT_IN_MEMORY_FALLBACK_ENABLED" in os.environ:
            app.config["RATELIMIT_IN_MEMORY_FALLBACK_ENABLED"] = os.environ[
                "RATELIMIT_IN_MEMORY_FALLBACK_ENABLED"
            ].lower() in ["true", "on", "1"]
        # Rate Limiting storage backend override (BLOGG-SEC-017)
        if "RATELIMIT_STORAGE_URI" in os.environ:
            app.config["RATELIMIT_STORAGE_URI"] = os.environ["RATELIMIT_STORAGE_URI"]
        if "RATELIMIT_SWALLOW_ERRORS" in os.environ:
            app.config["RATELIMIT_SWALLOW_ERRORS"] = os.environ[
                "RATELIMIT_SWALLOW_ERRORS"
            ].lower() in [
                "true",
                "on",
                "1",
            ]
        if "RATELIMIT_IN_MEMORY_FALLBACK_ENABLED" in os.environ:
            app.config["RATELIMIT_IN_MEMORY_FALLBACK_ENABLED"] = os.environ[
                "RATELIMIT_IN_MEMORY_FALLBACK_ENABLED"
            ].lower() in ["true", "on", "1"]


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
        secret_key = os.environ.get("SECRET_KEY")
        if not secret_key:
            raise RuntimeError("SECRET_KEY must be set in production")
        app.config["SECRET_KEY"] = secret_key

        mfa_key = os.environ.get("BLOGG_MFA_ENCRYPTION_KEY")
        if not mfa_key:
            raise RuntimeError(
                "BLOGG_MFA_ENCRYPTION_KEY environment variable must be set in production. "
                'Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
            )
        app.config["BLOGG_MFA_ENCRYPTION_KEY"] = mfa_key

        Config.init_app(app)

        # Validate rate limit backend in production (BLOGG-SEC-017)
        ratelimit_storage = app.config.get("RATELIMIT_STORAGE_URI", "memory://")
        if ratelimit_storage.startswith("redis://") or ratelimit_storage.startswith("rediss://"):
            app.logger.info(
                "Production rate limiting configured with distributed Redis backend: %s",
                sanitize_redis_uri(ratelimit_storage),
            )
        elif ratelimit_storage.startswith("memory://"):
            app.logger.warning(
                "Production rate limiting is using 'memory://' storage. "
                "Counters are not shared across multi-worker WSGI processes. "
                "For distributed deployments, set RATELIMIT_STORAGE_URI to a Redis backend (e.g. redis://host:port/0)."
            )
        elif ratelimit_storage.startswith("filesystem://"):
            app.logger.warning(
                "Production rate limiting is using 'filesystem://' storage. "
                "For high-concurrency production deployments, a Redis backend (redis://...) is recommended."
            )
        else:
            raise ValueError(
                f"Unsupported RATELIMIT_STORAGE_URI scheme: '{ratelimit_storage}'. "
                "Supported schemes: redis://, rediss://, memory://, filesystem://"
            )


config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
