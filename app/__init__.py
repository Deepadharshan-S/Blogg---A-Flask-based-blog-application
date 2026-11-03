import logging
import os
import secrets
import sqlite3
import time
from logging.handlers import RotatingFileHandler

import flask_moment
from flask import Flask, g, has_request_context, request
from flask_bootstrap import Bootstrap
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_mail import Mail
from flask_moment import Moment
from flask_pagedown import PageDown
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from markupsafe import Markup
from sqlalchemy import event
from sqlalchemy.engine import Engine

from config import config

login_manager = LoginManager()
login_manager.login_view = "auth.login"

bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()
pagedown = PageDown()
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["500 per day", "100 per hour"],
)

# Patch flask_moment.moment.include_moment to attach CSP nonce to its inline script
_orig_moment_include = flask_moment.moment.include_moment.__func__


@classmethod
def _nonce_aware_include_moment(cls, *args, **kwargs):
    rendered = str(_orig_moment_include(cls, *args, **kwargs))
    nonce = kwargs.get("nonce")
    if not nonce and has_request_context():
        nonce = getattr(g, "csp_nonce", None)
    if nonce:
        rendered = rendered.replace("<script>", f'<script nonce="{nonce}">')
    return Markup(rendered)


flask_moment.moment.include_moment = _nonce_aware_include_moment

# Patch flask_moment.moment._render to eliminate inline style="display: none" (violates CSP style-src)
_orig_moment_render = flask_moment.moment._render


def _clean_moment_render(self, *args, **kwargs):
    rendered = str(_orig_moment_render(self, *args, **kwargs))
    rendered = rendered.replace(' style="display: none"', "").replace(' style="display:none"', "")
    return Markup(rendered)


flask_moment.moment._render = _clean_moment_render

# Patch flask_pagedown to enforce HTTPS CDN and attach CSP nonces to scripts
import flask_pagedown.widgets

_orig_pagedown_include = flask_pagedown._pagedown.include_pagedown


def _nonce_aware_include_pagedown(self, *args, **kwargs):
    rendered = str(_orig_pagedown_include(self, *args, **kwargs))
    rendered = rendered.replace('src="//cdnjs.cloudflare.com', 'src="https://cdnjs.cloudflare.com')
    if has_request_context():
        nonce = getattr(g, "csp_nonce", None)
        if nonce:
            rendered = rendered.replace("<script", f'<script nonce="{nonce}"')
    return Markup(rendered)


flask_pagedown._pagedown.include_pagedown = _nonce_aware_include_pagedown
flask_pagedown._pagedown.html_head = _nonce_aware_include_pagedown

_orig_pagedown_call = flask_pagedown.widgets.PageDown.__call__


def _nonce_aware_pagedown_call(self, field, **kwargs):
    rendered = str(_orig_pagedown_call(self, field, **kwargs))
    if has_request_context():
        nonce = getattr(g, "csp_nonce", None)
        if nonce:
            rendered = rendered.replace(
                '<script type="text/javascript">',
                f'<script type="text/javascript" nonce="{nonce}">',
            )
    return Markup(rendered)


flask_pagedown.widgets.PageDown.__call__ = _nonce_aware_pagedown_call


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable SQLite foreign key enforcement for connections."""
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    pagedown.init_app(app)
    csrf.init_app(app)

    # Distributed Rate Limiting (BLOGG-SEC-017):
    # Dynamically bind error handling and in-memory degradation settings per app instance
    limiter._swallow_errors = bool(app.config.get("RATELIMIT_SWALLOW_ERRORS", True))
    limiter._in_memory_fallback_enabled = bool(
        app.config.get("RATELIMIT_IN_MEMORY_FALLBACK_ENABLED", True)
    )
    if "RATELIMIT_STORAGE_OPTIONS" not in app.config:
        app.config["RATELIMIT_STORAGE_OPTIONS"] = {
            "socket_connect_timeout": float(os.environ.get("BLOGG_REDIS_CONNECT_TIMEOUT", "1.5")),
            "socket_timeout": float(os.environ.get("BLOGG_REDIS_SOCKET_TIMEOUT", "1.5")),
        }
    limiter.init_app(app)

    # Register blueprints
    from .main import main as main_blueprint

    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint

    app.register_blueprint(auth_blueprint, url_prefix="/auth")

    from .admin import admin as admin_blueprint

    app.register_blueprint(admin_blueprint)

    from .api import api as api_blueprint

    csrf.exempt(api_blueprint)
    app.register_blueprint(api_blueprint, url_prefix="/api/v1")

    # App-scoped CLI commands (audit/access log retention, ...)
    from .cli import register_cli_commands

    register_cli_commands(app)

    # Per-request cryptographically secure CSP Nonce generation
    @app.before_request
    def set_csp_nonce():
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.context_processor
    def inject_csp_nonce():
        if not hasattr(g, "csp_nonce"):
            g.csp_nonce = secrets.token_urlsafe(16)
        return {"csp_nonce": g.csp_nonce}

    # Configure ProxyFix only if BLOGG_NUM_PROXIES is explicitly configured to > 0
    try:
        num_proxies = int(
            os.environ.get("BLOGG_NUM_PROXIES", app.config.get("BLOGG_NUM_PROXIES", 0))
        )
    except (ValueError, TypeError):
        num_proxies = 0

    if num_proxies > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=num_proxies,
            x_proto=num_proxies,
            x_host=num_proxies,
            x_prefix=num_proxies,
        )

    # Security Headers
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Content-Security-Policy with cryptographic nonce (BLOGG-SEC-014)
        nonce = getattr(g, "csp_nonce", None)
        if not nonce:
            nonce = secrets.token_urlsafe(16)
            g.csp_nonce = nonce

        csp_directives = [
            "default-src 'self'",
            f"script-src 'self' 'nonce-{nonce}' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net 'unsafe-hashes' 'sha256-47mKTaMaEn1L3m5DAz9muidMqw636xxw7EFAK/YnPdg='",
            "script-src-attr 'unsafe-hashes' 'sha256-47mKTaMaEn1L3m5DAz9muidMqw636xxw7EFAK/YnPdg='",
            f"style-src 'self' 'nonce-{nonce}' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net",
            "font-src 'self' https://fonts.gstatic.com data:",
            "img-src 'self' data: https://*.gravatar.com https://secure.gravatar.com https://www.gravatar.com",
            "connect-src 'self'",
            "frame-ancestors 'self'",
            "form-action 'self'",
            "base-uri 'self'",
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        # Strict-Transport-Security only in production deployments over HTTPS
        if not app.debug and not app.testing and request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        # Never cache pages or API payloads: after logout the back button
        # must re-fetch (and get an anonymous response), not replay a cached
        # authenticated view. Static assets keep their normal caching.
        content_type = response.content_type or ""
        if content_type.startswith("text/html") or content_type.startswith("application/json"):
            response.headers["Cache-Control"] = "no-store, private"
            response.headers["Pragma"] = "no-cache"
        return response

    # IAM: structured access log - one row per request (identity, path, status,
    # source IP, duration). Static assets and disabled deployments are filtered
    # inside record_access(); failures there never break the response.
    from .security import record_access

    @app.before_request
    def _access_log_start():
        g.pop("access_log_started", None)
        g.access_log_started = time.monotonic()

    @app.after_request
    def _access_log_record(response):
        started = g.pop("access_log_started", None)
        duration_ms = int((time.monotonic() - started) * 1000) if started is not None else None
        record_access(response, duration_ms=duration_ms)
        return response

    if not any(isinstance(h, RotatingFileHandler) for h in app.logger.handlers):
        if not os.path.exists("logs"):
            os.mkdir("logs")
        file_handler = RotatingFileHandler(
            "logs/blogg.log", maxBytes=10 * 1024 * 1024, backupCount=10
        )
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] in %(module)s: %(message)s")
        )
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info("Blogg startup")

    return app
