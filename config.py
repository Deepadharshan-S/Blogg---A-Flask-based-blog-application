import os

from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "01a17e0f0083fb73295dcf3d6455dbdc"
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

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    TEMPLATES_AUTO_RELOAD = True
    SQLALCHEMY_DATABASE_URI = os.environ.get("DEV_DATABASE_URL") or "sqlite:///" + os.path.join(
        basedir, "data-dev.sqlite"
    )


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get("TEST_DATABASE_URL") or "sqlite://"


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:///" + os.path.join(
        basedir, "data.sqlite"
    )

    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"

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
