"""B3: account deletion is an anonymizing tombstone, never a hard delete.

Deleting keeps posts, comments, likes and follows attached to the row but
strips every trace of the person: username/email become ``deleted_<id>``,
the password, MFA state and role are gone, all sessions and API tokens are
revoked, and the account can neither log in nor be resurrected. Reachable
self-service (security page), the admin console and the admin REST API.
"""

from app import db
from app.models import ApiToken, AuditEvent, Permission, Post, Role, User
from app.security import Event
from tests.iam_base import IAMTestCase


class AccountDeletionTestCase(IAMTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_user(
            email="root@example.com", username="root", role=self.admin_role()
        )
        self.user = self.make_user()
        self.post = Post(body="Post that outlives its author", author=self.user)
        db.session.add(self.post)
        db.session.commit()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _assert_tombstone(self, user):
        fresh = db.session.get(User, user.id)
        self.assertIsNotNone(fresh.deleted_at)
        self.assertTrue(fresh.username.startswith("deleted_"))
        self.assertIn("@example.invalid", fresh.email)
        self.assertIsNone(fresh.password_hash)
        self.assertFalse(fresh.active)
        self.assertFalse(fresh.confirmed)
        self.assertFalse(fresh.mfa_enabled)
        self.assertIsNone(fresh.mfa_secret)
        self.assertEqual(fresh.role.name, "User")  # demoted, no admin rights
        self.assertEqual(fresh.sessions.filter_by(revoked_at=None).count(), 0)
        self.assertEqual(ApiToken.query.filter_by(user_id=user.id).count(), 0)
        return fresh

    def _delete_self(self, password="Password123!", **kwargs):
        return self.post_form(
            "/auth/account/delete",
            {"password": password},
            page="/auth/security",
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Self-service deletion
    # ------------------------------------------------------------------
    def test_self_service_delete_anonymizes_and_signs_out(self):
        token = self.issue_token(
            email=self.user.email, password="Password123!", scopes=["tokens:manage"]
        )["token"]
        self.login()

        response = self._delete_self(follow_redirects=True)
        self.assertIn("Your account has been deleted", response.get_data(as_text=True))

        fresh = self._assert_tombstone(self.user)
        self.assertIsNotNone(
            AuditEvent.query.filter_by(event=Event.USER_DELETED, target_id=self.user.id).first()
        )

        # Signed out for real: the index renders anonymously again.
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/auth/security").status_code, 302)

        # The old credentials no longer authenticate anywhere.
        response = self.post_form(
            "/auth/login",
            {"email": "user@example.com", "password": "Password123!"},
            page="/auth/login",
            follow_redirects=True,
        )
        self.assertIn("Invalid username or password.", response.get_data(as_text=True))
        response = self.client.get("/api/v1/me/sessions", headers=self.api_headers(token))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(fresh.sessions.filter_by(revoked_at=None).count(), 0)

    def test_posts_survive_as_anonymous_tombstone(self):
        self.login()
        self._delete_self()

        self.assertEqual(Post.query.count(), 1)
        post = Post.query.first()
        self.assertTrue(post.author.username.startswith("deleted_"))
        # The author page still renders under the tombstone identity.
        response = self.client.get(f"/user/{post.author.username}")
        self.assertEqual(response.status_code, 200)

    def test_delete_requires_the_password(self):
        self.login()

        for password in ("wrong", ""):
            response = self._delete_self(password=password, follow_redirects=True)
            self.assertIn("Invalid password.", response.get_data(as_text=True))
            self.assertIsNone(db.session.get(User, self.user.id).deleted_at)
            self.assertTrue(db.session.get(User, self.user.id).active)

    def test_last_admin_cannot_delete_themselves(self):
        # self.admin is the only administrator.
        self.login(email=self.admin.email)

        response = self._delete_self(follow_redirects=True)
        self.assertIn(
            "You cannot delete the last administrator account.", response.get_data(as_text=True)
        )
        self.assertIsNone(db.session.get(User, self.admin.id).deleted_at)
        self.assertTrue(db.session.get(User, self.admin.id).active)

    # ------------------------------------------------------------------
    # Admin console
    # ------------------------------------------------------------------
    def test_admin_console_delete_user(self):
        self.login(email=self.admin.email)

        response = self.post_form(
            f"/admin/users/{self.user.id}",
            {"action": "delete_user"},
            page=f"/admin/users/{self.user.id}",
            follow_redirects=True,
        )
        self.assertIn("Account deleted", response.get_data(as_text=True))
        self._assert_tombstone(self.user)
        self.assertIsNotNone(
            AuditEvent.query.filter_by(
                event=Event.USER_DELETED,
                actor_id=self.admin.id,
                target_id=self.user.id,
            ).first()
        )

        # The tombstone shows up in the console but is frozen for actions.
        response = self.client.get(f"/admin/users/{self.user.id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("deleted", response.get_data(as_text=True))
        response = self.post_form(
            f"/admin/users/{self.user.id}",
            {"action": "toggle_active"},
            page=f"/admin/users/{self.user.id}",
            follow_redirects=True,
        )
        self.assertIn("no further actions are possible", response.get_data(as_text=True))
        self.assertFalse(db.session.get(User, self.user.id).active)

        # Admins delete others, not themselves, from the console.
        response = self.post_form(
            f"/admin/users/{self.admin.id}",
            {"action": "delete_user"},
            page=f"/admin/users/{self.admin.id}",
            follow_redirects=True,
        )
        self.assertIn("You cannot delete your own account here", response.get_data(as_text=True))
        self.assertIsNone(db.session.get(User, self.admin.id).deleted_at)

    def test_last_admin_protected_from_operator_deletion(self):
        ops_role = Role(name="Ops", permissions=Permission.MANAGE_USERS)
        db.session.add(ops_role)
        db.session.commit()
        ops = self.make_user(email="ops@example.com", username="ops", role=ops_role)
        token = self.issue_token(email=ops.email, password="Password123!", scopes=["admin"])[
            "token"
        ]

        # Web console.
        self.login(email=ops.email)
        response = self.post_form(
            f"/admin/users/{self.admin.id}",
            {"action": "delete_user"},
            page=f"/admin/users/{self.admin.id}",
            follow_redirects=True,
        )
        self.assertIn("Cannot delete the last administrator.", response.get_data(as_text=True))
        self.assertIsNone(db.session.get(User, self.admin.id).deleted_at)

        # Admin API.
        response = self.client.delete(
            f"/api/v1/admin/users/{self.admin.id}", headers=self.api_headers(token)
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("last administrator", response.get_json()["message"])
        self.assertIsNone(db.session.get(User, self.admin.id).deleted_at)

    # ------------------------------------------------------------------
    # Admin REST API
    # ------------------------------------------------------------------
    def test_admin_api_delete_user(self):
        admin_token = self.issue_token(
            email=self.admin.email, password="Password123!", scopes=["admin"]
        )["token"]
        headers = self.api_headers(admin_token)
        user_token = self.issue_token(email=self.user.email, password="Password123!")["token"]

        # Regular tokens cannot reach the endpoint.
        response = self.client.delete(
            f"/api/v1/admin/users/{self.user.id}", headers=self.api_headers(user_token)
        )
        self.assertEqual(response.status_code, 403)

        # Deleting yourself through the API is refused (use the security page).
        response = self.client.delete(f"/api/v1/admin/users/{self.admin.id}", headers=headers)
        self.assertEqual(response.status_code, 400)

        response = self.client.delete(f"/api/v1/admin/users/{self.user.id}", headers=headers)
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["deleted"])
        self.assertTrue(body["user"]["username"].startswith("deleted_"))
        self.assertIsNotNone(body["user"]["deleted_at"])
        self._assert_tombstone(self.user)

        # The tombstone can neither be deleted again nor resurrected.
        response = self.client.delete(f"/api/v1/admin/users/{self.user.id}", headers=headers)
        self.assertEqual(response.status_code, 400)
        response = self.client.patch(
            f"/api/v1/admin/users/{self.user.id}",
            headers=headers,
            json={"active": True},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("deleted", response.get_json()["message"].lower())

        # The deleted user's token died with them.
        response = self.client.get("/api/v1/me/sessions", headers=self.api_headers(user_token))
        self.assertEqual(response.status_code, 401)
