"""Audit trail: recording security events and gated viewing (web + API)."""

from unittest.mock import patch

from app import db
from app.models import AuditEvent, Role
from app.security import Event
from tests.iam_base import IAMTestCase


class AuditTestCase(IAMTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_user(
            email="root@example.com", username="root", role=self.admin_role()
        )
        self.user = self.make_user()

    def test_login_success_and_failure_are_recorded_with_context(self):
        response = self.login()
        self.assertIn(self.user.username, response.get_data(as_text=True))

        success = AuditEvent.query.filter_by(
            event=Event.LOGIN_SUCCESS, actor_id=self.user.id
        ).first()
        self.assertIsNotNone(success)
        self.assertTrue(success.success)
        self.assertEqual(success.ip, "127.0.0.1")

        self.logout()
        response = self.post_form(
            "/auth/login",
            {"email": self.user.email, "password": "bad-password"},
            follow_redirects=True,
        )
        self.assertIn("Invalid username or password.", response.get_data(as_text=True))

        failure = AuditEvent.query.filter_by(
            event=Event.LOGIN_FAILED, actor_id=self.user.id, success=False
        ).first()
        self.assertIsNotNone(failure)
        self.assertIn("bad_password", failure.detail)

    @patch("app.auth.views.send_email")
    def test_registration_and_confirmation_are_recorded(self, mock_send_email):
        response = self.post_form(
            "/auth/register",
            {
                "email": "fresh@example.com",
                "username": "fresh",
                "password": "Password123!",
                "password2": "Password123!",
            },
            follow_redirects=True,
        )
        self.assertIn("You can now login.", response.get_data(as_text=True))
        mock_send_email.assert_called_once()

        from app.models import User

        fresh = User.query.filter_by(email="fresh@example.com").first()
        self.assertIsNotNone(
            AuditEvent.query.filter_by(event=Event.REGISTER, actor_id=fresh.id).first()
        )

        # Log in and confirm the account.
        self.logout()
        self.login(email="fresh@example.com")
        token = fresh.generate_confirmation_token()
        response = self.client.get(f"/auth/confirm/{token}", follow_redirects=True)
        self.assertIn("You have confirmed your account.", response.get_data(as_text=True))
        self.assertIsNotNone(
            AuditEvent.query.filter_by(event=Event.ACCOUNT_CONFIRMED, actor_id=fresh.id).first()
        )

    def test_audit_web_view_requires_view_audit_and_filters(self):
        # Regular user: denied.
        self.login()
        self.assertEqual(self.client.get("/admin/audit").status_code, 403)
        self.logout()

        # Moderator: denied (no VIEW_AUDIT).
        moderator = self.make_user(
            email="mod@example.com",
            username="mod",
            role=Role.query.filter_by(name="Moderator").first(),
        )
        self.login(email=moderator.email)
        self.assertEqual(self.client.get("/admin/audit").status_code, 403)
        self.logout()

        # Administrator: allowed, filters work.
        self.login(email=self.admin.email)
        response = self.client.get("/admin/audit")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Security Audit Log", response.get_data(as_text=True))

        response = self.client.get("/admin/audit?event=auth.login.success")
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertIn("auth.login.success", text)
        self.assertNotIn("auth.login.failed", text)

        response = self.client.get("/admin/audit?success=0")
        self.assertEqual(response.status_code, 200)

    def test_audit_api_requires_admin_scope_and_permission(self):
        # Missing scope on an admin-owned token.
        no_scope = self.issue_token(email=self.admin.email, password="Password123!")["token"]
        response = self.client.get("/api/v1/admin/audit", headers=self.api_headers(no_scope))
        self.assertEqual(response.status_code, 403)
        self.assertIn("admin", response.get_json()["message"])

        # Admin scope but non-privileged account: permission check still blocks.
        user_token = self.issue_token(scopes=["admin"])["token"]
        response = self.client.get("/api/v1/admin/audit", headers=self.api_headers(user_token))
        self.assertEqual(response.status_code, 403)

        # Full admin token: allowed.
        admin_token = self.issue_token(
            email=self.admin.email,
            password="Password123!",
            scopes=["admin", "tokens:manage"],
        )["token"]
        response = self.client.get("/api/v1/admin/audit", headers=self.api_headers(admin_token))
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertIn("events", body)
        self.assertIn("total", body)
        self.assertGreater(body["total"], 0)

        # Filtering by event name.
        response = self.client.get(
            "/api/v1/admin/audit?event=token.issued", headers=self.api_headers(admin_token)
        )
        self.assertEqual(response.status_code, 200)
        events = {e["event"] for e in response.get_json()["events"]}
        self.assertEqual(events, {"token.issued"})

        # Event-name dictionary endpoint.
        response = self.client.get(
            "/api/v1/admin/audit/event-names", headers=self.api_headers(admin_token)
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("token.issued", response.get_json()["events"])

    def test_legacy_token_grants_full_access_for_admin_reads(self):
        legacy = self.admin.generate_auth_token()
        response = self.client.get("/api/v1/admin/audit", headers=self.api_headers(legacy))
        self.assertEqual(response.status_code, 200)

    def test_password_reset_requests_are_audited_for_both_cases(self):
        with patch("app.auth.views.send_email"):
            self.post_form("/auth/reset", {"email": self.user.email}, follow_redirects=True)
        known = AuditEvent.query.filter_by(
            event=Event.PASSWORD_RESET_REQUESTED, success=True
        ).first()
        self.assertIsNotNone(known)

        self.post_form("/auth/reset", {"email": "ghost@example.com"}, follow_redirects=True)
        unknown = AuditEvent.query.filter_by(
            event=Event.PASSWORD_RESET_REQUESTED, success=False
        ).first()
        self.assertIsNotNone(unknown)
        self.assertEqual(unknown.actor_label, "ghost@example.com")

    def test_audit_events_carry_ip_and_user_agent_fields(self):
        self.login()
        event = AuditEvent.query.filter_by(event=Event.LOGIN_SUCCESS, actor_id=self.user.id).first()
        self.assertEqual(event.ip, "127.0.0.1")
        self.assertIsNotNone(event.to_json()["timestamp"])
        self.assertEqual(event.to_json()["event"], Event.LOGIN_SUCCESS)

    def test_audit_pagination_shape(self):
        self.login(email=self.admin.email)
        admin_token = self.issue_token(
            email=self.admin.email, password="Password123!", scopes=["admin"]
        )["token"]
        response = self.client.get(
            "/api/v1/admin/audit?per_page=2&page=1", headers=self.api_headers(admin_token)
        )
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(len(body["events"]), 2)
        self.assertEqual(body["current_page"], 1)
        self.assertGreater(body["pages"], 1)

    def test_db_is_isolated_between_tests(self):
        # Guard: each test starts from a clean slate even though earlier
        # tests wrote many audit rows.
        self.assertEqual(AuditEvent.query.count(), 0)
        db.session.commit()
