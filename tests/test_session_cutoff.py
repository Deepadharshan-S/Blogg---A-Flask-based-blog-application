"""A4: the sessions_revoked_at cutoff refuses pre-revocation remember-me cookies.

Flask-Login's remember-me cookie carries no server-side session row to revoke,
so before this cutoff a remembered browser could resurrect a signed-out
account. Identities issued by get_id() embed the cutoff epoch in force at
issue time and load_user() refuses any identity whose tag no longer matches.
"""

from app import db
from app.models import User, load_user
from tests.iam_base import IAMTestCase


class SessionCutoffTestCase(IAMTestCase):
    """Remembered browsers must not survive a revocation."""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _remember_cookie_name(self):
        return self.app.config.get("REMEMBER_COOKIE_NAME", "remember_token")

    def _login_remembered(self, client=None, email="user@example.com", password="Password123!"):
        """Log in with "keep me logged in" and return (client, remember_cookie)."""
        client = client or self.client
        response = self.post_form(
            "/auth/login",
            {"email": email, "password": password, "remember_me": "y"},
            page="/auth/login",
            client=client,
        )
        self.assertEqual(response.status_code, 302, response.get_data(as_text=True))
        prefix = f"{self._remember_cookie_name()}="
        cookie = None
        for header in response.headers.getlist("Set-Cookie"):
            if header.startswith(prefix):
                cookie = header.split("=", 1)[1].split(";", 1)[0]
        self.assertIsNotNone(cookie, "remember_me login must set the remember cookie")
        return client, cookie

    def _remembered_browser(self, cookie):
        """A fresh browser carrying only the remember-me cookie (no session)."""
        client = self.app.test_client()
        client.set_cookie(self._remember_cookie_name(), cookie)
        return client

    def _is_signed_in(self, client):
        """GET /auth/security: 200 means authenticated, redirect means anonymous."""
        return client.get("/auth/security").status_code == 200

    def _revoke_all(self, client=None):
        return self.post_form(
            "/auth/security/sessions/revoke-all",
            {},
            page="/auth/security",
            client=client or self.client,
        )

    # ------------------------------------------------------------------
    # Control: remember-me works when nothing was revoked
    # ------------------------------------------------------------------
    def test_remembered_browser_is_signed_in_before_any_revocation(self):
        self.make_user()
        _, cookie = self._login_remembered()
        browser = self._remembered_browser(cookie)
        self.assertTrue(self._is_signed_in(browser))

    # ------------------------------------------------------------------
    # A4 core: a revocation kills pre-revocation remember cookies
    # ------------------------------------------------------------------
    def test_remembered_browser_is_refused_after_revoke_all(self):
        self.make_user()
        _, cookie = self._login_remembered()
        self._revoke_all()
        browser = self._remembered_browser(cookie)
        self.assertFalse(self._is_signed_in(browser))

    def test_fresh_login_after_revocation_issues_working_remember_cookie(self):
        self.make_user()
        _, stale_cookie = self._login_remembered()
        self._revoke_all()
        # A fresh password login after the cutoff issues a tagged identity.
        _, fresh_cookie = self._login_remembered()
        self.assertTrue(self._is_signed_in(self._remembered_browser(fresh_cookie)))
        # The pre-revocation cookie stays dead even though a newer one works.
        self.assertFalse(self._is_signed_in(self._remembered_browser(stale_cookie)))

    def test_revoke_others_keeps_this_device_and_kills_remembered_others(self):
        self.make_user()
        client_a, _ = self._login_remembered()
        _, cookie_b = self._login_remembered()
        response = self.post_form(
            "/auth/security/sessions/revoke-others",
            {},
            page="/auth/security",
            client=client_a,
        )
        self.assertEqual(response.status_code, 302, response.get_data(as_text=True))
        # This device stays signed in: its identity tag was re-stamped.
        self.assertTrue(self._is_signed_in(client_a))
        # The other device's remembered cookie is refused.
        self.assertFalse(self._is_signed_in(self._remembered_browser(cookie_b)))

    def test_change_password_kills_other_remembered_devices(self):
        self.make_user()
        client_a, _ = self._login_remembered()
        _, cookie_b = self._login_remembered()
        response = self.post_form(
            "/auth/change-password",
            {
                "old_password": "Password123!",
                "password": "NewPassword123!",
                "password2": "NewPassword123!",
            },
            page="/auth/change-password",
            client=client_a,
        )
        self.assertEqual(response.status_code, 302, response.get_data(as_text=True))
        self.assertTrue(self._is_signed_in(client_a))
        self.assertFalse(self._is_signed_in(self._remembered_browser(cookie_b)))

    # ------------------------------------------------------------------
    # Identity parsing: legacy plain ids, stale tags, garbage
    # ------------------------------------------------------------------
    def test_identity_epoch_gating_at_load_user(self):
        user = self.make_user()
        stale_identity = user.get_id()  # tagged with epoch 0 (no cutoff yet)
        self.assertTrue(stale_identity.startswith(f"{user.id}."))

        # A legacy plain "id" identity loads while no cutoff is in force.
        self.assertEqual(load_user(str(user.id)), user)

        user.revoke_sessions()
        db.session.commit()

        # Everything issued before the cutoff is refused...
        self.assertIsNone(load_user(stale_identity))
        self.assertIsNone(load_user(str(user.id)))
        # ...while an identity issued after it is valid again.
        self.assertEqual(load_user(user.get_id()), user)

    def test_garbage_identities_are_refused(self):
        self.assertIsNone(load_user("not-a-user"))
        self.assertIsNone(load_user(""))
        self.assertIsNone(load_user(None))
        self.assertIsNone(load_user(f"{'9' * 12}.banana"))

    def test_parse_identity_shapes(self):
        self.assertEqual(User.parse_identity("42"), (42, 0))
        self.assertEqual(User.parse_identity("42.1760000000"), (42, 1760000000))
        self.assertEqual(User.parse_identity("42."), (42, 0))
        self.assertEqual(User.parse_identity("abc"), (None, 0))
        self.assertEqual(User.parse_identity(None), (None, 0))
