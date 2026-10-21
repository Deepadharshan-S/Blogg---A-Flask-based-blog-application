import logging
import os
import sqlite3
from logging.handlers import RotatingFileHandler

from flask import Flask, request
from flask_bootstrap import Bootstrap
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_mail import Mail
from flask_moment import Moment
from flask_pagedown import PageDown
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
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
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)


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

        # Content-Security-Policy tailored to Blogg frontend assets and integrations
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com http://cdnjs.cloudflare.com https://cdn.jsdelivr.net http://cdn.jsdelivr.net",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com http://fonts.googleapis.com https://cdnjs.cloudflare.com http://cdnjs.cloudflare.com https://cdn.jsdelivr.net http://cdn.jsdelivr.net",
            "font-src 'self' https://fonts.gstatic.com http://fonts.gstatic.com data:",
            "img-src 'self' data: https://*.gravatar.com http://*.gravatar.com https://secure.gravatar.com http://secure.gravatar.com https://www.gravatar.com http://www.gravatar.com",
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

    if not os.path.exists("logs"):
        os.mkdir("logs")
    file_handler = RotatingFileHandler("logs/blogg.log", maxBytes=10 * 1024 * 1024, backupCount=10)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] in %(module)s: %(message)s")
    )
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info("Blogg startup")

    return app
