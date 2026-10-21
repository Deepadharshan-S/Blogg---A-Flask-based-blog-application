"""Password reset & password-history policy tests."""

from unittest.mock import patch

from app import db
from app.models import AuditEvent
from app.security import Event
from tests.iam_base import IAMTestCase


class PasswordResetTestCase(IAMTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.make_user()

    @patch("app.auth.views.send_email")
    def test_reset_request_unknown_email_does_not_enumerate(self, mock_send_email):
        """Unknown addresses get the same generic response and are audited."""
        response = self.post_form(
            "/auth/reset", {"email": "ghost@example.com"}, follow_redirects=True
        )
        text = response.get_data(as_text=True)
        self.assertIn(
            "An email with instructions to reset your password has been sent to you.", text
        )
        mock_send_email.assert_not_called()

        event = AuditEvent.query.filter_by(event=Event.PASSWORD_RESET_REQUESTED).first()
        self.assertIsNotNone(event)
        self.assertFalse(event.success)
        self.assertEqual(event.actor_label, "ghost@example.com")

    @patch("app.auth.views.send_email")
    def test_reset_request_known_email_sends_token(self, mock_send_email):
        response = self.post_form("/auth/reset", {"email": self.user.email}, follow_redirects=True)
        self.assertIn("has been sent to you", response.get_data(as_text=True))
        mock_send_email.assert_called_once()
        event = AuditEvent.query.filter_by(
            event=Event.PASSWORD_RESET_REQUESTED, success=True
        ).first()
        self.assertIsNotNone(event)
        self.assertEqual(event.actor_id, self.user.id)

    def test_reset_flow_with_valid_token(self):
        """A signed reset link sets a new password and archives the old hash."""
        token = self.user.generate_reset_token()
        response = self.post_form(
            f"/auth/reset/{token}",
            {"password": "BrandNew1!", "password2": "BrandNew1!"},
            follow_redirects=True,
        )
        self.assertIn("Your password has been updated.", response.get_data(as_text=True))

        db.session.refresh(self.user)
        self.assertTrue(self.user.verify_password("BrandNew1!"))
        self.assertFalse(self.user.verify_password("Password123!"))
        self.assertGreaterEqual(self.user.password_history.count(), 1)
        self.assertIsNotNone(self.user.password_changed_at)

        event = AuditEvent.query.filter_by(event=Event.PASSWORD_RESET_COMPLETED).first()
        self.assertIsNotNone(event)
        self.assertEqual(event.actor_id, self.user.id)

        # Old password rejected at login, new password accepted.
        response = self.post_form(
            "/auth/login",
            {"email": self.user.email, "password": "Password123!"},
            follow_redirects=True,
        )
        self.assertIn("Invalid username or password.", response.get_data(as_text=True))
        response = self.login()
        self.assertIn(self.user.username, response.get_data(as_text=True))

    def test_reset_with_tampered_token_rejected(self):
        response = self.post_form(
            "/auth/reset/not-a-real-token",
            {"password": "BrandNew1!", "password2": "BrandNew1!"},
            follow_redirects=True,
        )
        self.assertIn(
            "The password reset link is invalid or has expired.", response.get_data(as_text=True)
        )
        db.session.refresh(self.user)
        self.assertTrue(self.user.verify_password("Password123!"))

    def test_change_password_rejects_reuse(self):
        self.login()
        # First change succeeds.
        response = self.post_form(
            "/auth/change-password",
            {
                "old_password": "Password123!",
                "password": "SecondPass1!",
                "password2": "SecondPass1!",
            },
            page="/auth/change-password",
            follow_redirects=True,
        )
        self.assertIn("Your password has been updated.", response.get_data(as_text=True))

        # Reusing the current password is rejected.
        response = self.post_form(
            "/auth/change-password",
            {
                "old_password": "SecondPass1!",
                "password": "SecondPass1!",
                "password2": "SecondPass1!",
            },
            page="/auth/change-password",
            follow_redirects=True,
        )
        self.assertIn("You cannot reuse a recent password.", response.get_data(as_text=True))

        # Reverting to a password kept in history is rejected too.
        response = self.post_form(
            "/auth/change-password",
            {
                "old_password": "SecondPass1!",
                "password": "Password123!",
                "password2": "Password123!",
            },
            page="/auth/change-password",
            follow_redirects=True,
        )
        self.assertIn("You cannot reuse a recent password.", response.get_data(as_text=True))
        db.session.refresh(self.user)
        self.assertTrue(self.user.verify_password("SecondPass1!"))

    def test_change_password_revokes_other_sessions_and_audits(self):
        client_b = self.app.test_client()
        self.login()
        self.login(client=client_b)

        response = self.post_form(
            "/auth/change-password",
            {
                "old_password": "Password123!",
                "password": "SecondPass1!",
                "password2": "SecondPass1!",
            },
            page="/auth/change-password",
            follow_redirects=True,
        )
        self.assertIn("Your password has been updated.", response.get_data(as_text=True))

        event = AuditEvent.query.filter_by(event=Event.PASSWORD_CHANGED).first()
        self.assertIsNotNone(event)

        # The other browser session was signed out.
        other = client_b.get("/")
        self.assertEqual(other.status_code, 302)
        self.assertIn("/auth/login", other.headers["Location"])

        # The current session survives.
        current = self.client.get("/")
        self.assertEqual(current.status_code, 200)

    def test_wrong_old_password_rejected(self):
        self.login()
        response = self.post_form(
            "/auth/change-password",
            {
                "old_password": "WrongOld1!",
                "password": "SecondPass1!",
                "password2": "SecondPass1!",
            },
            page="/auth/change-password",
            follow_redirects=True,
        )
        self.assertIn("Invalid password.", response.get_data(as_text=True))
        db.session.refresh(self.user)
        self.assertTrue(self.user.verify_password("Password123!"))
