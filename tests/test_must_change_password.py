"""B1: an admin-issued forced password change gates web and API access.

While ``must_change_password`` is set, every web request bounces to the
change-password form (logout stays reachable) and API credentials return
403 ``password change required`` until a new password is set — which clears
the flag (self-service change or an email reset both satisfy it).
"""

from app import db
from app.models import AuditEvent, User
from app.security import Event
from tests.iam_base import IAMTestCase


class MustChangePasswordTestCase(IAMTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_user(
            email="root@example.com", username="root", role=self.admin_role()
        )
        self.user = self.make_user()
        self.user_client = self.app.test_client()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _admin_toggles_flag(self, expected):
        """Press the admin console's force-password-change button once."""
        self.login(email=self.admin.email)
        response = self.post_form(
            f"/admin/users/{self.user.id}",
            {"action": "force_password_change"},
            page=f"/admin/users/{self.user.id}",
        )
        self.assertEqual(response.status_code, 302, response.get_data(as_text=True))
        self.assertIs(db.session.get(User, self.user.id).must_change_password, expected)

    def _login_user_fresh(self):
        """Password login without following the redirect, to inspect landing."""
        return self.post_form(
            "/auth/login",
            {"email": self.user.email, "password": "Password123!"},
            page="/auth/login",
            client=self.user_client,
        )

    # ------------------------------------------------------------------
    # Web enforcement
    # ------------------------------------------------------------------
    def test_admin_requires_change_and_web_is_gated_until_done(self):
        self._admin_toggles_flag(True)

        # The action is audited against the acting administrator.
        event = AuditEvent.query.filter_by(
            event=Event.USER_PASSWORD_CHANGE_REQUIRED,
            actor_id=self.admin.id,
            target_id=self.user.id,
        ).first()
        self.assertIsNotNone(event)

        # A fresh login lands straight on the change-password form.
        login = self._login_user_fresh()
        self.assertEqual(login.status_code, 302)
        self.assertEqual(login.headers["Location"], "/auth/change-password")

        # Every other page bounces back to the form...
        for path in ("/", "/auth/security", "/auth/login"):
            response = self.user_client.get(path)
            self.assertEqual(response.status_code, 302, path)
            self.assertEqual(response.headers["Location"], "/auth/change-password", path)

        # ...while the form itself stays reachable.
        self.assertEqual(self.user_client.get("/auth/change-password").status_code, 200)

    def test_satisfying_the_change_clears_the_flag_and_restores_access(self):
        self._admin_toggles_flag(True)
        self._login_user_fresh()

        response = self.post_form(
            "/auth/change-password",
            {
                "old_password": "Password123!",
                "password": "SecondPass1!",
                "password2": "SecondPass1!",
            },
            page="/auth/change-password",
            client=self.user_client,
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertIn("Your password has been updated.", response.get_data(as_text=True))
        self.assertFalse(db.session.get(User, self.user.id).must_change_password)

        # Access is restored on the very next request.
        self.assertEqual(self.user_client.get("/").status_code, 200)

    def test_flagged_user_can_still_log_out(self):
        self._admin_toggles_flag(True)
        self._login_user_fresh()

        # Logout is explicitly allowed while flagged.
        response = self.post_form(
            "/auth/logout",
            {},
            page="/auth/change-password",
            client=self.user_client,
            follow_redirects=True,
        )
        self.assertIn("You have been logged out.", response.get_data(as_text=True))
        # Really signed out: the index renders anonymously again.
        self.assertEqual(self.user_client.get("/").status_code, 200)

    def test_plain_user_cannot_use_the_force_change_action(self):
        self.login(client=self.user_client)
        response = self.post_form(
            f"/admin/users/{self.admin.id}",
            {"action": "force_password_change"},
            page="/auth/security",
            client=self.user_client,
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(db.session.get(User, self.admin.id).must_change_password)

    # ------------------------------------------------------------------
    # API enforcement
    # ------------------------------------------------------------------
    def test_api_credentials_are_frozen_until_the_flag_clears(self):
        token = self.issue_token(
            email=self.user.email, password="Password123!", scopes=["tokens:manage"]
        )["token"]
        headers = self.api_headers(token)
        self.assertEqual(self.client.get("/api/v1/me/sessions", headers=headers).status_code, 200)

        self._admin_toggles_flag(True)

        response = self.client.get("/api/v1/me/sessions", headers=headers)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"], "password change required")

        # Clearing the flag unfreezes the API again.
        self._admin_toggles_flag(False)
        self.assertEqual(self.client.get("/api/v1/me/sessions", headers=headers).status_code, 200)

    def test_admin_api_patch_sets_and_clears_the_flag(self):
        admin_token = self.issue_token(
            email=self.admin.email, password="Password123!", scopes=["admin"]
        )["token"]
        headers = self.api_headers(admin_token)

        response = self.client.patch(
            f"/api/v1/admin/users/{self.user.id}",
            headers=headers,
            json={"must_change_password": True},
        )
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["changed"])
        self.assertTrue(body["changes"]["must_change_password"])
        self.assertTrue(body["user"]["must_change_password"])
        self.assertTrue(db.session.get(User, self.user.id).must_change_password)
        self.assertIsNotNone(
            AuditEvent.query.filter_by(
                event=Event.USER_PASSWORD_CHANGE_REQUIRED, target_id=self.user.id
            ).first()
        )

        # Re-patching the same value is a no-op.
        response = self.client.patch(
            f"/api/v1/admin/users/{self.user.id}",
            headers=headers,
            json={"must_change_password": True},
        )
        self.assertFalse(response.get_json()["changed"])

        # And it can be cleared again.
        response = self.client.patch(
            f"/api/v1/admin/users/{self.user.id}",
            headers=headers,
            json={"must_change_password": False},
        )
        self.assertTrue(response.get_json()["changed"])
        self.assertFalse(db.session.get(User, self.user.id).must_change_password)

        # A regular user's token has no business at the admin endpoint.
        user_token = self.issue_token(email=self.user.email, password="Password123!")["token"]
        response = self.client.patch(
            f"/api/v1/admin/users/{self.user.id}",
            headers=self.api_headers(user_token),
            json={"must_change_password": True},
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(db.session.get(User, self.user.id).must_change_password)

    # ------------------------------------------------------------------
    # Credential paths that satisfy the forced change
    # ------------------------------------------------------------------
    def test_email_reset_satisfies_the_forced_change(self):
        user = self.make_user(email="forced@example.com", username="forced")
        user.must_change_password = True
        db.session.commit()

        token = user.generate_reset_token()
        recovered = User.reset_password(token, "ThirdPass1!")
        self.assertTrue(recovered)
        self.assertFalse(db.session.get(User, user.id).must_change_password)
