"""B2: opt-in password expiry via BLOGG_PASSWORD_MAX_AGE_DAYS (off by default).

When enabled, a password older than the configured maximum age is forced
through the change-password form exactly like the B1 admin flag, and API
credentials answer 403 ``password expired`` until the password is renewed.
"""

from datetime import datetime, timedelta, timezone

from app import db
from tests.iam_base import IAMTestCase


class PasswordExpiryTestCase(IAMTestCase):
    MAX_AGE = 30

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _age_password(self, user, days):
        user.password_changed_at = datetime.now(timezone.utc) - timedelta(days=days)
        db.session.commit()

    def _login(self):
        return self.post_form(
            "/auth/login",
            {"email": "user@example.com", "password": "Password123!"},
            page="/auth/login",
        )

    def _change_password(self):
        return self.post_form(
            "/auth/change-password",
            {
                "old_password": "Password123!",
                "password": "SecondPass1!",
                "password2": "SecondPass1!",
            },
            page="/auth/change-password",
            follow_redirects=True,
        )

    # ------------------------------------------------------------------
    # Policy is opt-in
    # ------------------------------------------------------------------
    def test_expiry_is_off_by_default(self):
        self.assertEqual(self.app.config["BLOGG_PASSWORD_MAX_AGE_DAYS"], 0)
        user = self.make_user()
        self._age_password(user, 4000)  # far beyond any sane policy

        response = self._login()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_fresh_password_is_not_gated_when_enabled(self):
        self.app.config["BLOGG_PASSWORD_MAX_AGE_DAYS"] = self.MAX_AGE
        self.make_user()  # password set just now

        response = self._login()
        self.assertEqual(response.headers["Location"], "/")
        self.assertEqual(self.client.get("/").status_code, 200)

    # ------------------------------------------------------------------
    # Enforcement
    # ------------------------------------------------------------------
    def test_expired_password_is_gated_on_login_and_web(self):
        self.app.config["BLOGG_PASSWORD_MAX_AGE_DAYS"] = self.MAX_AGE
        user = self.make_user()
        self._age_password(user, 100)

        # A fresh login lands straight on the change-password form...
        response = self._login()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/auth/change-password")

        # ...and the rest of the site bounces there too.
        for path in ("/", "/auth/security"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302, path)
            self.assertEqual(response.headers["Location"], "/auth/change-password", path)

    def test_changing_an_expired_password_unblocks_access(self):
        self.app.config["BLOGG_PASSWORD_MAX_AGE_DAYS"] = self.MAX_AGE
        user = self.make_user()
        self._age_password(user, 100)
        self._login()

        response = self._change_password()
        self.assertIn("Your password has been updated.", response.get_data(as_text=True))
        # The setter refreshed password_changed_at, so the policy is satisfied.
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_api_is_frozen_with_an_expired_password(self):
        self.app.config["BLOGG_PASSWORD_MAX_AGE_DAYS"] = self.MAX_AGE
        user = self.make_user()
        token = self.issue_token(scopes=["tokens:manage"])["token"]
        headers = self.api_headers(token)
        self.assertEqual(self.client.get("/api/v1/me/sessions", headers=headers).status_code, 200)

        self._age_password(user, 100)

        response = self.client.get("/api/v1/me/sessions", headers=headers)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"], "password expired")

        # Renewing the password unfreezes the token again.
        self._login()
        self._change_password()
        self.assertEqual(self.client.get("/api/v1/me/sessions", headers=headers).status_code, 200)

    def test_member_since_fallback_for_legacy_rows(self):
        self.app.config["BLOGG_PASSWORD_MAX_AGE_DAYS"] = self.MAX_AGE
        user = self.make_user()
        # A legacy account with no recorded password change falls back to
        # the account's age instead of being expired instantly.
        user.password_changed_at = None
        user.member_since = datetime.now(timezone.utc) - timedelta(days=100)
        db.session.commit()

        response = self._login()
        self.assertEqual(response.headers["Location"], "/auth/change-password")
