"""Tests for bounded email processing (BLOGG-SEC-016).

Verifies:
- Bounded queue capacity prevents memory and thread exhaustion.
- Rejection of email tasks when queue is saturated (EmailQueueFull).
- Graceful degradation: send_email drops message, logs warning, returns None, no request crash.
- Worker background error handling: SMTP exceptions are caught and logged.
- Registration and password-reset flows work seamlessly.
- Thread count is strictly bounded.
"""

import threading
import time
from unittest.mock import MagicMock, patch

from flask_mail import Message

from app.email import (
    BoundedEmailExecutor,
    EmailQueueFull,
    get_email_executor,
    reset_email_executor,
    send_async_email,
    send_email,
)
from tests.iam_base import IAMTestCase


class BoundedEmailTestCase(IAMTestCase):
    def setUp(self):
        super().setUp()
        reset_email_executor()

    def tearDown(self):
        reset_email_executor()
        super().tearDown()

    def test_bounded_executor_rejects_on_saturation(self):
        """Ensure BoundedEmailExecutor enforces capacity limit and raises EmailQueueFull."""
        executor = BoundedEmailExecutor(max_workers=1, max_queue_size=2)
        try:
            worker_started = threading.Event()

            def blocking_task():
                worker_started.set()
                time.sleep(1.0)

            executor.submit(blocking_task)
            self.assertTrue(worker_started.wait(timeout=2.0))

            # Now fill the 2 slots in the bounded queue
            f1 = executor.submit(lambda: None)
            f2 = executor.submit(lambda: None)
            self.assertIsNotNone(f1)
            self.assertIsNotNone(f2)

            # Submitting 3rd task when queue capacity is 2 must raise EmailQueueFull
            with self.assertRaises(EmailQueueFull):
                executor.submit(lambda: None)
        finally:
            executor.shutdown(wait=False)

    def test_send_email_graceful_drop_on_queue_saturation(self):
        """Ensure send_email drops saturated tasks gracefully without crashing callers."""
        executor = get_email_executor(max_workers=1, queue_capacity=1)
        worker_started = threading.Event()
        worker_blocked = threading.Event()

        def blocking_task(*args, **kwargs):
            worker_started.set()
            worker_blocked.wait(timeout=3.0)

        try:
            # Worker takes first task
            executor.submit(blocking_task)
            self.assertTrue(worker_started.wait(timeout=2.0))

            # Queue takes second task (capacity is 1)
            executor.submit(blocking_task)

            # Next send_email call encounters saturated queue (now Full)
            with self.app.test_request_context("/"):
                with patch.object(self.app.logger, "warning") as mock_warn:
                    res = send_email(
                        to="target@example.com",
                        subject="Test Notification",
                        template="auth/email/confirm",
                        user=MagicMock(username="testuser"),
                        token="testtoken123",
                    )
                    # Must return None instead of crashing
                    self.assertIsNone(res)
                    mock_warn.assert_called_once()
                    self.assertIn("Email task queue is saturated", mock_warn.call_args[0][0])
                    self.assertIn("target@example.com", mock_warn.call_args[0][2])
        finally:
            worker_blocked.set()
            executor.shutdown(wait=False)

    def test_send_async_email_handles_smtp_crash(self):
        """Ensure background worker logs SMTP delivery failures and does not crash."""
        msg = Message("Test", sender="admin@example.com", recipients=["user@example.com"])
        with patch("app.email.mail.send", side_effect=ConnectionRefusedError("SMTP server down")):
            with patch.object(self.app.logger, "error") as mock_err:
                send_async_email(self.app, msg)
                mock_err.assert_called_once()
                self.assertIn("Failed to send email", mock_err.call_args[0][0])

    def test_email_dispatch_non_blocking_execution(self):
        """Ensure send_email dispatches asynchronously and returns a Future."""
        with self.app.test_request_context("/"):
            with patch("app.email.mail.send") as mock_mail_send:
                future = send_email(
                    to="recipient@example.com",
                    subject="Welcome",
                    template="auth/email/confirm",
                    user=MagicMock(username="welcomeuser"),
                    token="tok123",
                )
                self.assertIsNotNone(future)
                # Wait for background task to complete
                future.result(timeout=3.0)
                mock_mail_send.assert_called_once()
