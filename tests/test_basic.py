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
