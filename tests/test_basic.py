import os
import unittest
from unittest.mock import patch

from flask import current_app
from flask_mail import Message

from app import create_app, db
from app.email import send_async_email


class BasicsTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_app_exists(self):
        self.assertFalse(current_app is None)

    def test_app_is_testing(self):
        self.assertTrue(current_app.config["TESTING"])

    def test_production_config_secret_key_guard(self):
        """Ensure ProductionConfig requires SECRET_KEY in environment."""
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError) as ctx:
                create_app("production")
            self.assertIn("SECRET_KEY must be set in production", str(ctx.exception))

        with patch.dict(os.environ, {"SECRET_KEY": "super-secret-prod-key"}):
            prod_app = create_app("production")
            self.assertEqual(prod_app.config["SECRET_KEY"], "super-secret-prod-key")

    def test_shutdown_route_removed(self):
        """Ensure legacy /shutdown route no longer exists and returns 404."""
        client = self.app.test_client()
        response = client.get("/shutdown")
        self.assertEqual(response.status_code, 404)

    def test_send_async_email_handles_and_logs_exception(self):
        """Ensure background email worker logs SMTP errors instead of raising unhandled exception."""
        msg = Message("Test Subject", sender="test@example.com", recipients=["to@example.com"])
        with patch("app.email.mail.send", side_effect=RuntimeError("SMTP connection failed")):
            with patch.object(self.app.logger, "error") as mock_log:
                send_async_email(self.app, msg)
                mock_log.assert_called_once()
                self.assertIn("Failed to send email", mock_log.call_args[0][0])

    def test_send_async_email_success(self):
        """Ensure background email worker calls mail.send when successful."""
        msg = Message("Test Subject", sender="test@example.com", recipients=["to@example.com"])
        with patch("app.email.mail.send") as mock_send:
            send_async_email(self.app, msg)
            mock_send.assert_called_once_with(msg)

    def test_logging_handler_max_bytes(self):
        """Ensure RotatingFileHandler uses a 10MB threshold."""
        from logging.handlers import RotatingFileHandler

        rotating_handlers = [
            h for h in self.app.logger.handlers if isinstance(h, RotatingFileHandler)
        ]
        self.assertTrue(len(rotating_handlers) > 0)
        self.assertEqual(rotating_handlers[0].maxBytes, 10 * 1024 * 1024)

    def test_ratelimit_storage_uri_configuration(self):
        """Ensure RATELIMIT_STORAGE_URI is configured on app."""
        self.assertIn("RATELIMIT_STORAGE_URI", self.app.config)
        self.assertEqual(self.app.config["RATELIMIT_STORAGE_URI"], "memory://")

    def test_production_cookie_security_attributes(self):
        """Ensure ProductionConfig sets Secure, HttpOnly, and SameSite cookie attributes."""
        with patch.dict(os.environ, {"SECRET_KEY": "super-secret-prod-key"}):
            prod_app = create_app("production")
            self.assertTrue(prod_app.config["SESSION_COOKIE_SECURE"])
            self.assertTrue(prod_app.config["SESSION_COOKIE_HTTPONLY"])
            self.assertEqual(prod_app.config["SESSION_COOKIE_SAMESITE"], "Lax")
            self.assertTrue(prod_app.config["REMEMBER_COOKIE_SECURE"])
            self.assertTrue(prod_app.config["REMEMBER_COOKIE_HTTPONLY"])
            self.assertEqual(prod_app.config["REMEMBER_COOKIE_SAMESITE"], "Lax")

    def test_bounded_email_executor(self):
        """Ensure email executor is bounded and handles task submissions."""
        from app.email import get_email_executor

        executor = get_email_executor(max_workers=2)
        self.assertIsNotNone(executor)
        self.assertLessEqual(executor._max_workers, 4)

    def test_proxyfix_configuration(self):
        """Ensure ProxyFix middleware is applied only when BLOGG_NUM_PROXIES > 0."""
        from werkzeug.middleware.proxy_fix import ProxyFix

        # 1. Default (no proxies) -> standard wsgi_app without ProxyFix
        with patch.dict(os.environ, {"BLOGG_NUM_PROXIES": "0"}):
            app_direct = create_app("testing")
            self.assertNotIsInstance(app_direct.wsgi_app, ProxyFix)

        # 2. Configured with 1 proxy -> wsgi_app is wrapped with ProxyFix
        with patch.dict(os.environ, {"BLOGG_NUM_PROXIES": "1"}):
            app_proxy = create_app("testing")
            self.assertIsInstance(app_proxy.wsgi_app, ProxyFix)
            self.assertEqual(app_proxy.wsgi_app.x_for, 1)

    def test_security_headers_and_csp(self):
        """BLOGG-SEC-011: Ensure security headers (CSP, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection=0, HSTS) are correctly configured."""
        client = self.app.test_client()
        res = client.get("/")

        # Standard baseline headers
        self.assertEqual(res.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(res.headers.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertEqual(res.headers.get("X-XSS-Protection"), "0")
        self.assertEqual(res.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")

        # Content-Security-Policy
        csp = res.headers.get("Content-Security-Policy", "")
        self.assertIn("default-src 'self'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertIn("style-src 'self'", csp)
        self.assertIn("font-src 'self'", csp)
        self.assertIn("img-src 'self'", csp)
        self.assertIn("connect-src 'self'", csp)

        # HSTS must NOT be emitted in testing or development over HTTP
        self.assertNotIn("Strict-Transport-Security", res.headers)

        # HSTS MUST be emitted in production deployments when connection is HTTPS
        with patch.dict(os.environ, {"SECRET_KEY": "super-secret-prod-key"}):
            prod_app = create_app("production")
            prod_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"
            with prod_app.app_context():
                db.create_all()
            prod_client = prod_app.test_client()

            # HTTPS request receives HSTS
            res_https = prod_client.get("/", base_url="https://localhost")
            self.assertEqual(res_https.headers.get("Strict-Transport-Security"), "max-age=31536000")

            # HTTP request does not receive HSTS
            res_http = prod_client.get("/", base_url="http://localhost")
            self.assertNotIn("Strict-Transport-Security", res_http.headers)
