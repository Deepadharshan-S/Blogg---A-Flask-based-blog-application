"""TOTP enrollment, login challenge, backup codes and API OTP tests."""

import re

import pyotp

from app import db
from app.models import AuditEvent, User
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

    def test_disable_form_posts_to_the_disable_endpoint(self):
        """The rendered disable form must target the POST-only route.

        quick_form() defaults to action="", which submits to the current URL.
        /auth/security only accepts GET, so the form used to return 405 Method
        Not Allowed and users could never switch 2FA off from the UI.
        """
        self._enable_mfa()
        self._login_with_mfa()

        text = self.client.get("/auth/security").get_data(as_text=True)
        # The tempered dot keeps the match inside one <form>...</form> block so
        # an earlier form's action (e.g. the navbar search) can't be matched.
        match = re.search(
            r'<form[^>]*action="([^"]*)"[^>]*>(?:(?!</form>).)*name="password"'
            r"(?:(?!</form>).)*Disable two-factor",
            text,
            re.S,
        )
        self.assertIsNotNone(match, "disable form not found on /auth/security")
        self.assertEqual(match.group(1), "/auth/security/mfa/disable")

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

    def test_successful_mfa_login_resets_failure_counter(self):
        """A completed 2FA login must clear earlier failures, not keep them.

        authenticate_credentials() returns AUTH_MFA_REQUIRED before it reaches
        reset_login_failures(), so without an explicit reset in the challenge
        view a user at 4/5 failures stays at 4 after logging in successfully
        and locks out on the very next typo. The counter must NOT be cleared
        when the challenge is issued though, otherwise an attacker could reset
        it with every password submit and brute-force OTPs.
        """
        self._enable_mfa()
        self.user.failed_login_attempts = 4
        db.session.add(self.user)
        db.session.commit()

        self.login()
        # Reaching the challenge does not touch the counter.
        self.assertEqual(db.session.get(User, self.user.id).failed_login_attempts, 4)

        response = self.post_form(
            "/auth/mfa", {"code": self._totp()}, page="/auth/mfa", follow_redirects=True
        )
        self.assertIn("Two-factor authentication verified.", response.get_data(as_text=True))

        fresh = db.session.get(User, self.user.id)
        self.assertEqual(fresh.failed_login_attempts, 0)
        self.assertFalse(fresh.is_locked)

        # The counter restarts from zero: one later typo counts as one
        # failure instead of pushing a still-stale 4 straight to a lockout.
        self.logout()
        self.login()
        response = self.post_form(
            "/auth/mfa", {"code": "000000"}, page="/auth/mfa", follow_redirects=True
        )
        self.assertIn("Invalid authentication code.", response.get_data(as_text=True))
        fresh = db.session.get(User, self.user.id)
        self.assertEqual(fresh.failed_login_attempts, 1)
        self.assertFalse(fresh.is_locked)

    def test_backup_codes_can_be_regenerated(self):
        old_codes = self._enable_mfa()
        self._login_with_mfa()

        response = self.post_form(
            "/auth/security/mfa/backup-codes",
            {},
            page="/auth/security",
            follow_redirects=True,
        )
        text = response.get_data(as_text=True)
        self.assertIn("New backup codes generated", text)
        # The new set is revealed exactly like at enrolment (once).
        self.assertIn("Save your backup codes now", text)

        new_codes = re.findall(r"<code>([0-9a-f]{4}-[0-9a-f]{4})</code>", text)
        self.assertEqual(len(new_codes), 10)

        # The previous set is dead and the new one verifies.
        self.assertFalse(self.user.verify_mfa_code(old_codes[0]))
        self.assertEqual(len(self.user.backup_code_hashes()), 10)
        self.assertTrue(self.user.verify_mfa_code(new_codes[0]))

        self.assertIsNotNone(
            AuditEvent.query.filter_by(
                event=Event.MFA_BACKUP_CODES_REGEN, actor_id=self.user.id
            ).first()
        )

        # Shown only once: a later visit no longer prints them.
        response = self.client.get("/auth/security")
        self.assertNotIn("Save your backup codes now", response.get_data(as_text=True))

    def test_backup_code_regeneration_requires_mfa(self):
        self.login()
        response = self.post_form(
            "/auth/security/mfa/backup-codes",
            {},
            page="/auth/security",
            follow_redirects=True,
        )
        self.assertIn("Two-factor authentication is not enabled.", response.get_data(as_text=True))
        self.assertIsNone(self.user.backup_code_hashes() or None)
