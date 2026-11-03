"""Tests for session fixation defense and pre-auth state clearance (BLOGG-SEC-013).

Verifies:
- All pre-authentication session keys are wiped on login.
- Injected pre-login keys/cookies cannot be hijacked across authentication boundary.
- Staged redirect target is safely preserved and validated.
- MFA transition clears pre-auth session state while preserving navigation.
- Remember-me cookies function correctly post-clearance.
- Fresh UserSession and JTI are issued in pristine session context.
"""

from app import db
from app.models import UserSession
from tests.iam_base import IAMTestCase


class SessionFixationTestCase(IAMTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.make_user()

    def test_pre_login_session_data_cleared_on_login(self):
        """Ensure pre-authentication session values are purged upon successful login."""
        # 1. Establish pre-authentication session state as anonymous user
        with self.client.session_transaction() as flask_session:
            flask_session["attacker_probe"] = "malicious_token_123"
            flask_session["anonymous_cart"] = ["item_1", "item_2"]

        # 2. Log in as authentic user
        response = self.login()
        self.assertEqual(response.status_code, 200)

        # 3. Verify pre-login keys were wiped from session
        with self.client.session_transaction() as flask_session:
            self.assertNotIn("attacker_probe", flask_session)
            self.assertNotIn("anonymous_cart", flask_session)
            # Authenticated session identifiers must be present
            self.assertIn("session_jti", flask_session)
            self.assertIn("_user_id", flask_session)

    def test_staged_redirect_preserved_and_safe_url_enforced(self):
        """Ensure staged post-login redirect is honored if safe and purged if unsafe."""
        # A. Safe relative redirect
        with self.client.session_transaction() as flask_session:
            flask_session["next"] = "/auth/security"
            flask_session["pre_auth_noise"] = "noise"

        response = self.post_form(
            "/auth/login",
            {"email": self.user.email, "password": "Password123!"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/auth/security")

        with self.client.session_transaction() as flask_session:
            self.assertNotIn("pre_auth_noise", flask_session)
            self.assertNotIn("next", flask_session)

        self.logout()

        # B. Unsafe external open-redirect attempt is rejected
        with self.client.session_transaction() as flask_session:
            flask_session["next"] = "https://attacker.example.com/steal"

        response = self.post_form(
            "/auth/login",
            {"email": self.user.email, "password": "Password123!"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        # Defaults to safe home page rather than external URL
        self.assertEqual(response.headers["Location"], "/")

    def test_mfa_flow_session_fixation_mitigation(self):
        """Ensure MFA completion purges intermediate pre-auth keys and starts fresh session."""
        self.user.generate_mfa_secret()
        self.user.mfa_enabled = True
        db.session.add(self.user)
        db.session.commit()

        # Seed pre-auth session data
        with self.client.session_transaction() as flask_session:
            flask_session["pre_mfa_junk"] = "should_be_cleared"

        # Step 1: Submit password
        res = self.post_form(
            "/auth/login?next=/auth/security",
            {"email": self.user.email, "password": "Password123!"},
            follow_redirects=False,
        )
        self.assertEqual(res.status_code, 302)
        self.assertIn("/auth/mfa", res.headers["Location"])

        # Step 2: Submit valid MFA code
        import pyotp

        totp = pyotp.TOTP(self.user.mfa_secret).now()
        res_mfa = self.post_form(
            "/auth/mfa",
            {"code": totp},
            page="/auth/mfa",
            follow_redirects=False,
        )
        self.assertEqual(res_mfa.status_code, 302)
        self.assertEqual(res_mfa.headers["Location"], "/auth/security")

        # Verify intermediate and pre-auth keys are gone
        with self.client.session_transaction() as flask_session:
            self.assertNotIn("pre_mfa_junk", flask_session)
            self.assertNotIn("mfa_user_id", flask_session)
            self.assertNotIn("mfa_remember", flask_session)
            self.assertIn("session_jti", flask_session)

    def test_remember_me_functionality_with_session_clear(self):
        """Ensure remember-me cookie is issued and functional across session regeneration."""
        response = self.post_form(
            "/auth/login",
            {"email": self.user.email, "password": "Password123!", "remember_me": "y"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        # Flask-Login sets the remember cookie
        self.assertTrue(any("remember_token" in h for h in response.headers.getlist("Set-Cookie")))

        with self.client.session_transaction() as flask_session:
            jti = flask_session.get("session_jti")
            self.assertIsNotNone(jti)

        db_session = db.session.get(UserSession, jti)
        self.assertIsNotNone(db_session)
        self.assertEqual(db_session.user_id, self.user.id)
