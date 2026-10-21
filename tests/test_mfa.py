"""TOTP enrollment, login challenge, backup codes and API OTP tests."""

import pyotp

from app import db
from app.models import AuditEvent
from app.security import Event
from tests.iam_base import IAMTestCase


class MFATestCase(IAMTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.make_user()
        self.backup_codes = None

    def _enable_mfa(self):
        """Enable TOTP + backup codes directly (no enrollment flow)."""
        self.user.generate_mfa_secret()
        self.user.mfa_enabled = True
        self.backup_codes = self.user.generate_backup_codes()
        db.session.add(self.user)
        db.session.commit()
        return self.backup_codes

    def _totp(self):
        return pyotp.TOTP(self.user.mfa_secret).now()

    def _login_with_mfa(self, client=None):
        """Log in and complete the MFA challenge, returning the final response."""
        self.login(client=client)
        return self.post_form(
            "/auth/mfa",
            {"code": self._totp()},
            page="/auth/mfa",
            client=client,
            follow_redirects=True,
        )

    def test_enrollment_flow_shows_backup_codes_once(self):
        self.login()

        response = self.client.get("/auth/security/mfa/setup")
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.user.mfa_secret, response.get_data(as_text=True))
        self.assertFalse(self.user.mfa_enabled)

        response = self.post_form(
            "/auth/security/mfa/setup",
            {"code": self._totp()},
            page="/auth/security/mfa/setup",
            follow_redirects=True,
        )
        self.assertTrue(self.user.mfa_enabled)
        self.assertEqual(len(self.user.backup_code_hashes()), 10)
        self.assertIsNotNone(self.user.mfa_secret)

        text = response.get_data(as_text=True)
        self.assertIn("Save your backup codes now", text)
        self.assertIn("Two-factor authentication is now enabled.", text)

        event = AuditEvent.query.filter_by(event=Event.MFA_ENABLED, actor_id=self.user.id).first()
        self.assertIsNotNone(event)

        # Backup codes are shown only once.
        response = self.client.get("/auth/security")
        self.assertNotIn("Save your backup codes now", response.get_data(as_text=True))

    def test_enrollment_rejects_wrong_code(self):
        self.login()
        response = self.post_form(
            "/auth/security/mfa/setup",
            {"code": "000000"},
            page="/auth/security/mfa/setup",
            follow_redirects=True,
        )
        self.assertIn("did not verify", response.get_data(as_text=True))
        self.assertFalse(self.user.mfa_enabled)

    def test_login_requires_second_factor(self):
        self._enable_mfa()

        # Password alone redirects to the MFA challenge instead of logging in.
        response = self.post_form(
            "/auth/login",
            {"email": self.user.email, "password": "Password123!"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/mfa", response.headers["Location"])

        # Wrong code is rejected.
        response = self.post_form(
            "/auth/mfa", {"code": "000000"}, page="/auth/mfa", follow_redirects=True
        )
        self.assertIn("Invalid authentication code.", response.get_data(as_text=True))

        # Correct TOTP code completes the login.
        response = self.post_form(
            "/auth/mfa", {"code": self._totp()}, page="/auth/mfa", follow_redirects=True
        )
        text = response.get_data(as_text=True)
        self.assertIn("Two-factor authentication verified.", text)
        self.assertIn(self.user.username, text)

        self.assertIsNotNone(
            AuditEvent.query.filter_by(event=Event.MFA_SUCCESS, actor_id=self.user.id).first()
        )

    def test_backup_code_is_single_use(self):
        codes = self._enable_mfa()
        first_code = codes[0]

        self.login()
        response = self.post_form(
            "/auth/mfa", {"code": first_code}, page="/auth/mfa", follow_redirects=True
        )
        self.assertIn("Two-factor authentication verified.", response.get_data(as_text=True))

        # Sign out and try the same backup code again - it was consumed.
        self.logout()
        self.login()
        response = self.post_form(
            "/auth/mfa", {"code": first_code}, page="/auth/mfa", follow_redirects=True
        )
        self.assertIn("Invalid authentication code.", response.get_data(as_text=True))
        self.assertEqual(len(self.user.backup_code_hashes()), 9)

    def test_api_token_issuance_requires_otp(self):
        self._enable_mfa()

        response = self.client.post(
            "/api/v1/tokens",
            headers=self.api_headers(),
            json={"email": self.user.email, "password": "Password123!"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("Multi-factor authentication required", response.get_json()["message"])

        # With a valid OTP (JSON field) the token is issued.
        response = self.client.post(
            "/api/v1/tokens",
            headers=self.api_headers(),
            json={"email": self.user.email, "password": "Password123!", "otp": self._totp()},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["token"])

        # ...and with the X-MFA-OTP header as well.
        headers = self.api_headers()
        headers["X-MFA-OTP"] = self._totp()
        response = self.client.post(
            "/api/v1/tokens",
            headers=headers,
            json={"email": self.user.email, "password": "Password123!"},
        )
        self.assertEqual(response.status_code, 200)

    def test_disable_mfa_requires_password(self):
        self._enable_mfa()
        response = self._login_with_mfa()
        self.assertIn("Two-factor authentication verified.", response.get_data(as_text=True))

        response = self.post_form(
            "/auth/security/mfa/disable",
            {"password": "NotMyPassword1!"},
            page="/auth/security",
            follow_redirects=True,
        )
        self.assertIn("Invalid password.", response.get_data(as_text=True))
        self.assertTrue(self.user.mfa_enabled)

        response = self.post_form(
            "/auth/security/mfa/disable",
            {"password": "Password123!"},
            page="/auth/security",
            follow_redirects=True,
        )
        self.assertIn(
            "Two-factor authentication has been disabled.", response.get_data(as_text=True)
        )
        self.assertFalse(self.user.mfa_enabled)
        self.assertIsNone(self.user.mfa_secret)
        self.assertIsNotNone(
            AuditEvent.query.filter_by(event=Event.MFA_DISABLED, actor_id=self.user.id).first()
        )
