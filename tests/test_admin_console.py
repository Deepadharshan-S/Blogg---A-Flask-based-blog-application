"""Admin console + admin REST API: RBAC, user lifecycle, role guards."""

from app import db
from app.models import AuditEvent, Permission, Role, User
from app.security import Event
from tests.iam_base import IAMTestCase


class AdminConsoleTestCase(IAMTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_user(
            email="root@example.com", username="root", role=self.admin_role()
        )
        self.user = self.make_user()
        self.moderator_role = Role.query.filter_by(name="Moderator").first()
        self.user_role = Role.query.filter_by(name="User").first()

    # ------------------------------------------------------------------
    # Access control
    # ------------------------------------------------------------------
    def test_admin_requires_login(self):
        response = self.client.get("/admin/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/login", response.headers["Location"])

    def test_admin_denied_to_non_privileged_users(self):
        self.login()
        response = self.client.get("/admin/")
        self.assertEqual(response.status_code, 403)
        response = self.client.get("/admin/users")
        self.assertEqual(response.status_code, 403)
        response = self.client.get("/admin/audit")
        self.assertEqual(response.status_code, 403)

    def test_moderator_has_no_admin_console_access(self):
        moderator = self.make_user(
            email="mod@example.com", username="mod", role=self.moderator_role
        )
        self.login(email=moderator.email)
        self.assertEqual(self.client.get("/admin/").status_code, 403)
        # Moderator also cannot read the audit log.
        self.assertEqual(self.client.get("/admin/audit").status_code, 403)

    def test_admin_sees_dashboard_users_and_audit(self):
        self.login(email=self.admin.email)
        response = self.client.get("/admin/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Admin Console", response.get_data(as_text=True))

        response = self.client.get("/admin/users")
        self.assertIn(self.user.username, response.get_data(as_text=True))

        response = self.client.get(f"/admin/users/{self.user.id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.user.email, response.get_data(as_text=True))

        response = self.client.get("/admin/audit")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Security Audit Log", response.get_data(as_text=True))

    # ------------------------------------------------------------------
    # User lifecycle actions
    # ------------------------------------------------------------------
    def test_role_change_via_console_is_audited(self):
        self.login(email=self.admin.email)
        response = self.post_form(
            f"/admin/users/{self.user.id}",
            {"action": "role", "role_id": self.moderator_role.id},
            page=f"/admin/users/{self.user.id}",
            follow_redirects=True,
        )
        self.assertIn("is now Moderator.", response.get_data(as_text=True))
        self.assertEqual(self.user.role.name, "Moderator")

        event = AuditEvent.query.filter_by(
            event=Event.USER_ROLE_CHANGED, actor_id=self.admin.id, target_id=self.user.id
        ).first()
        self.assertIsNotNone(event)
        self.assertIn("Moderator", event.detail)

    def test_disable_user_revokes_sessions_and_blocks_login(self):
        client_b = self.app.test_client()
        self.login(email=self.user.email, client=client_b)

        self.login(email=self.admin.email)
        response = self.post_form(
            f"/admin/users/{self.user.id}",
            {"action": "toggle_active"},
            page=f"/admin/users/{self.user.id}",
            follow_redirects=True,
        )
        self.assertIn("Account disabled and sessions revoked.", response.get_data(as_text=True))
        self.assertFalse(self.user.active)

        # Existing session dies immediately.
        response_b = client_b.get("/")
        self.assertEqual(response_b.status_code, 302)
        self.assertIn("/auth/login", response_b.headers["Location"])

        # New login attempts are rejected with a clear message.
        response = self.post_form(
            "/auth/login",
            {"email": self.user.email, "password": "Password123!"},
            follow_redirects=True,
        )
        self.assertIn("disabled", response.get_data(as_text=True))

        self.assertIsNotNone(
            AuditEvent.query.filter_by(
                event=Event.USER_DISABLED, actor_id=self.admin.id, target_id=self.user.id
            ).first()
        )

        # Re-enable restores access.
        self.logout()
        self.login(email=self.admin.email)
        self.post_form(
            f"/admin/users/{self.user.id}",
            {"action": "toggle_active"},
            page=f"/admin/users/{self.user.id}",
            follow_redirects=True,
        )
        self.assertTrue(self.user.active)
        self.logout()
        response = self.login()
        self.assertIn(self.user.username, response.get_data(as_text=True))

    def test_admin_cannot_change_own_role(self):
        self.login(email=self.admin.email)
        response = self.post_form(
            f"/admin/users/{self.admin.id}",
            {"action": "role", "role_id": self.user_role.id},
            page=f"/admin/users/{self.admin.id}",
            follow_redirects=True,
        )
        self.assertIn(
            "Use another administrator account to change your own role.",
            response.get_data(as_text=True),
        )
        self.assertEqual(self.admin.role.name, "Administrator")

    def test_admin_cannot_disable_own_account(self):
        self.login(email=self.admin.email)
        response = self.post_form(
            f"/admin/users/{self.admin.id}",
            {"action": "toggle_active"},
            page=f"/admin/users/{self.admin.id}",
            follow_redirects=True,
        )
        self.assertIn("You cannot disable your own account.", response.get_data(as_text=True))
        self.assertTrue(self.admin.active)

    def test_last_administrator_protection(self):
        """A MANAGE_USERS operator cannot demote/disable the only admin."""
        ops_role = Role(name="Ops", permissions=Permission.MANAGE_USERS | Permission.VIEW_AUDIT)
        db.session.add(ops_role)
        db.session.commit()
        ops = self.make_user(email="ops@example.com", username="ops", role=ops_role)

        self.login(email=ops.email)
        # Demotion blocked.
        response = self.post_form(
            f"/admin/users/{self.admin.id}",
            {"action": "role", "role_id": self.user_role.id},
            page=f"/admin/users/{self.admin.id}",
            follow_redirects=True,
        )
        self.assertIn("Cannot demote the last administrator.", response.get_data(as_text=True))
        self.assertEqual(self.admin.role.name, "Administrator")

        # Disabling blocked.
        response = self.post_form(
            f"/admin/users/{self.admin.id}",
            {"action": "toggle_active"},
            page=f"/admin/users/{self.admin.id}",
            follow_redirects=True,
        )
        self.assertIn("Cannot disable the last administrator.", response.get_data(as_text=True))
        self.assertTrue(self.admin.active)

    def test_legacy_edit_profile_admin_enforces_self_role_guard(self):
        """The older /edit-profile/<id> route honours the same role guards."""
        self.login(email=self.admin.email)
        response = self.post_form(
            f"/edit-profile/{self.admin.id}",
            {
                "email": self.admin.email,
                "username": self.admin.username,
                "confirmed": "y",
                "role": str(self.user_role.id),
            },
            page=f"/edit-profile/{self.admin.id}",
            follow_redirects=True,
        )
        self.assertIn(
            "Use another administrator account to change your own role.",
            self.page_text(response),
        )
        self.assertEqual(self.admin.role.name, "Administrator")

        # A permitted change (different user, non-last admin) still works and is audited.
        target = self.make_user(email="target@example.com", username="target")
        response = self.post_form(
            f"/edit-profile/{target.id}",
            {
                "email": target.email,
                "username": target.username,
                "confirmed": "y",
                "role": self.moderator_role.id,
            },
            page=f"/edit-profile/{target.id}",
            follow_redirects=True,
        )
        self.assertIn("The profile has been updated.", self.page_text(response))
        self.assertEqual(target.role.name, "Moderator")
        change = (
            AuditEvent.query.filter_by(event=Event.USER_ROLE_CHANGED, target_id=target.id)
            .order_by(AuditEvent.id.desc())
            .first()
        )
        self.assertIsNotNone(change)
        self.assertIn("edit_profile_admin", str(change.detail))

    def test_confirm_and_password_reset_actions(self):
        unconfirmed = self.make_user(
            email="pending@example.com", username="pending", confirmed=False
        )
        self.login(email=self.admin.email)

        response = self.post_form(
            f"/admin/users/{unconfirmed.id}",
            {"action": "confirm"},
            page=f"/admin/users/{unconfirmed.id}",
            follow_redirects=True,
        )
        self.assertIn("Account marked as confirmed.", response.get_data(as_text=True))
        self.assertTrue(unconfirmed.confirmed)

        from unittest.mock import patch

        with patch("app.admin.views.send_email") as mock_send:
            response = self.post_form(
                f"/admin/users/{unconfirmed.id}",
                {"action": "send_reset"},
                page=f"/admin/users/{unconfirmed.id}",
                follow_redirects=True,
            )
        mock_send.assert_called_once()
        self.assertIn("Password reset email sent", response.get_data(as_text=True))
        self.assertIsNotNone(
            AuditEvent.query.filter_by(
                event=Event.USER_PASSWORD_RESET_SENT, actor_id=self.admin.id
            ).first()
        )

    # ------------------------------------------------------------------
    # Role management
    # ------------------------------------------------------------------
    def test_role_crud_with_guards(self):
        self.login(email=self.admin.email)

        # Create.
        response = self.post_form(
            "/admin/roles/new",
            {"name": "Editor", "write": "y", "comment": "y"},
            page="/admin/roles/new",
            follow_redirects=True,
        )
        self.assertIn("Role 'Editor' created.", self.page_text(response))
        editor = Role.query.filter_by(name="Editor").first()
        self.assertIsNotNone(editor)
        self.assertEqual(editor.permissions, Permission.WRITE | Permission.COMMENT)
        self.assertIsNotNone(
            AuditEvent.query.filter_by(event=Event.ROLE_CREATED, target_label="Editor").first()
        )

        # Duplicate name rejected.
        response = self.post_form(
            "/admin/roles/new", {"name": "Editor"}, page="/admin/roles/new", follow_redirects=True
        )
        self.assertIn("already exists", response.get_data(as_text=True))

        # Built-in roles cannot be deleted.
        response = self.post_form(
            f"/admin/roles/{self.admin_role().id}/delete",
            {},
            page="/admin/roles",
            follow_redirects=True,
        )
        self.assertIn("Built-in roles cannot be deleted.", response.get_data(as_text=True))
        self.assertIsNotNone(db.session.get(Role, self.admin_role().id))

        # Built-in roles cannot be renamed.
        response = self.post_form(
            f"/admin/roles/{self.admin_role().id}/edit",
            {"name": "Boss"},
            page=f"/admin/roles/{self.admin_role().id}/edit",
            follow_redirects=True,
        )
        self.assertIn("Built-in roles cannot be renamed.", response.get_data(as_text=True))
        self.assertEqual(self.admin_role().name, "Administrator")

        # Edit custom role permissions.
        response = self.post_form(
            f"/admin/roles/{editor.id}/edit",
            {"name": "Editor", "moderate": "y", "write": "y"},
            page=f"/admin/roles/{editor.id}/edit",
            follow_redirects=True,
        )
        self.assertIn("Role 'Editor' updated.", self.page_text(response))
        db.session.refresh(editor)
        self.assertEqual(editor.permissions, Permission.WRITE | Permission.MODERATE)

        # Roles with users cannot be deleted.
        self.user.role = editor
        db.session.commit()
        response = self.post_form(
            f"/admin/roles/{editor.id}/delete", {}, page="/admin/roles", follow_redirects=True
        )
        self.assertIn("Reassign users away", response.get_data(as_text=True))

        # Empty custom role can be deleted.
        self.user.role = self.user_role
        db.session.commit()
        response = self.post_form(
            f"/admin/roles/{editor.id}/delete", {}, page="/admin/roles", follow_redirects=True
        )
        self.assertIn("Role 'Editor' deleted.", self.page_text(response))
        self.assertIsNone(db.session.get(Role, editor.id))

    def test_role_edit_cannot_strip_last_admin_permission(self):
        ops_role = Role(name="Ops", permissions=Permission.MANAGE_USERS)
        db.session.add(ops_role)
        db.session.commit()
        ops = self.make_user(email="ops2@example.com", username="ops2", role=ops_role)

        # 'ops' has MANAGE_USERS but not ADMIN, so role editing is denied entirely.
        self.login(email=ops.email)
        admin_role = self.admin_role()
        self.assertEqual(self.client.get(f"/admin/roles/{admin_role.id}/edit").status_code, 403)

        self.logout()
        self.login(email=self.admin.email)
        response = self.post_form(
            f"/admin/roles/{admin_role.id}/edit",
            {"name": "Administrator", "manage_users": "y", "view_audit": "y"},
            page=f"/admin/roles/{admin_role.id}/edit",
            follow_redirects=True,
        )
        self.assertIn("Cannot remove the ADMIN permission", response.get_data(as_text=True))
        self.assertTrue(admin_role.has_admin)

    # ------------------------------------------------------------------
    # Admin REST API
    # ------------------------------------------------------------------
    def _admin_token(self, scopes=None):
        return self.issue_token(
            email=self.admin.email, password="Password123!", scopes=scopes or ["admin"]
        )["token"]

    def test_admin_api_requires_scope_and_permission(self):
        # Default-scoped token lacks the admin scope.
        default_token = self.issue_token(email=self.admin.email, password="Password123!")["token"]
        response = self.client.get("/api/v1/admin/users", headers=self.api_headers(default_token))
        self.assertEqual(response.status_code, 403)
        self.assertIn("admin", response.get_json()["message"])

        # A regular user may request the scope but lacks the RBAC permission.
        user_token = self.issue_token(scopes=["admin"])["token"]
        response = self.client.get("/api/v1/admin/users", headers=self.api_headers(user_token))
        self.assertEqual(response.status_code, 403)

        # Unauthenticated.
        response = self.client.get("/api/v1/admin/users")
        self.assertEqual(response.status_code, 401)

        # Admin with the scope succeeds.
        token = self._admin_token()
        response = self.client.get("/api/v1/admin/users", headers=self.api_headers(token))
        self.assertEqual(response.status_code, 200)
        emails = [u["email"] for u in response.get_json()["users"]]
        self.assertIn(self.admin.email, emails)
        self.assertIn(self.user.email, emails)

    def test_admin_api_user_search_and_patch(self):
        token = self._admin_token()
        headers = self.api_headers(token)

        response = self.client.get("/api/v1/admin/users?q=root", headers=headers)
        self.assertEqual(response.status_code, 200)
        users = response.get_json()["users"]
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["email"], self.admin.email)
        self.assertTrue(users[0]["mfa_enabled"] is False)

        # Change role.
        response = self.client.patch(
            f"/api/v1/admin/users/{self.user.id}",
            headers=headers,
            json={"role": "Moderator"},
        )
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["changed"])
        self.assertEqual(body["user"]["role"], "Moderator")

        # Disable.
        response = self.client.patch(
            f"/api/v1/admin/users/{self.user.id}",
            headers=headers,
            json={"active": False},
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["user"]["active"])
        self.assertEqual(
            self.user.sessions.filter_by(revoked_at=None).count(),
            0,
        )

        # Self guards over the API.
        response = self.client.patch(
            f"/api/v1/admin/users/{self.admin.id}",
            headers=headers,
            json={"role": "User"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("another administrator", response.get_json()["message"])

        response = self.client.patch(
            f"/api/v1/admin/users/{self.admin.id}",
            headers=headers,
            json={"active": False},
        )
        self.assertEqual(response.status_code, 400)

        # Unknown role.
        response = self.client.patch(
            f"/api/v1/admin/users/{self.user.id}",
            headers=headers,
            json={"role": "NoSuchRole"},
        )
        self.assertEqual(response.status_code, 400)

    def test_admin_api_role_lifecycle(self):
        token = self._admin_token()
        headers = self.api_headers(token)

        response = self.client.get("/api/v1/admin/roles", headers=headers)
        self.assertEqual(response.status_code, 200)
        names = [r["name"] for r in response.get_json()["roles"]]
        self.assertIn("Administrator", names)

        response = self.client.post(
            "/api/v1/admin/roles",
            headers=headers,
            json={"name": "QA", "permissions": ["COMMENT", "FOLLOW"]},
        )
        self.assertEqual(response.status_code, 201)
        role = Role.query.filter_by(name="QA").first()
        self.assertEqual(role.permissions, Permission.COMMENT | Permission.FOLLOW)

        # Unknown permission name.
        response = self.client.post(
            "/api/v1/admin/roles",
            headers=headers,
            json={"name": "Bad", "permissions": ["ROOT"]},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Unknown permission", response.get_json()["message"])

        # Built-in deletion refused.
        response = self.client.delete(
            f"/api/v1/admin/roles/{self.admin_role().id}", headers=headers
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Built-in", response.get_json()["message"])

        # Custom role deleted.
        response = self.client.delete(f"/api/v1/admin/roles/{role.id}", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(db.session.get(Role, role.id))

    def test_admin_api_helpers_unlock_reset_mfa_and_sessions(self):
        target = User.query.filter_by(email=self.user.email).first()
        target.mfa_enabled = True
        target.generate_mfa_secret()
        target.lock(minutes=15)
        db.session.add(target)
        db.session.commit()

        token = self._admin_token()
        headers = self.api_headers(token)

        response = self.client.post(f"/api/v1/admin/users/{target.id}/unlock", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(target.is_locked)
        self.assertIsNotNone(
            AuditEvent.query.filter_by(
                event=Event.USER_UNLOCKED, actor_id=self.admin.id, target_id=target.id
            ).first()
        )

        response = self.client.delete(f"/api/v1/admin/users/{target.id}/mfa", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(target.mfa_enabled)
        self.assertIsNone(target.mfa_secret)

        from unittest.mock import patch

        with patch("app.api.admin.send_email") as mock_send:
            response = self.client.post(
                f"/api/v1/admin/users/{target.id}/password-reset", headers=headers
            )
        self.assertEqual(response.status_code, 200)
        mock_send.assert_called_once()

        response = self.client.delete(f"/api/v1/admin/users/{target.id}/sessions", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["revoked_count"], 0)
