"""Server-side session management: device list, revocation and timeouts."""

from datetime import timedelta

from app import db
from app.models import AuditEvent, UserSession, utc_now
from app.security import Event
from tests.iam_base import IAMTestCase


class SessionManagementTestCase(IAMTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.make_user()

    def _current_jti(self, client=None):
        client = client or self.client
        with client.session_transaction() as flask_session:
            return flask_session.get("session_jti")

    def test_login_creates_a_tracked_session(self):
        response = self.login()
        self.assertIn(self.user.username, response.get_data(as_text=True))

        sessions = UserSession.query.filter_by(user_id=self.user.id, revoked_at=None).all()
        self.assertEqual(len(sessions), 1)
        self.assertIsNotNone(sessions[0].ip)
        self.assertIsNotNone(
            AuditEvent.query.filter_by(event=Event.SESSION_STARTED, actor_id=self.user.id).first()
        )

        response = self.client.get("/auth/security")
        text = response.get_data(as_text=True)
        self.assertIn("Active Sessions", text)
        self.assertIn("This device", text)

    def test_revoking_another_device_signs_it_out(self):
        client_b = self.app.test_client()
        self.login()
        self.login(client=client_b)
        self.assertEqual(
            UserSession.query.filter_by(user_id=self.user.id, revoked_at=None).count(), 2
        )

        jti_a = self._current_jti()
        jti_b = self._current_jti(client_b)
        self.assertNotEqual(jti_a, jti_b)

        response = self.post_form(
            f"/auth/security/sessions/{jti_b}/revoke",
            {},
            page="/auth/security",
            follow_redirects=True,
        )
        self.assertIn("That session has been revoked.", response.get_data(as_text=True))

        # Device B is logged out on its next request.
        response_b = client_b.get("/")
        self.assertEqual(response_b.status_code, 302)
        self.assertIn("/auth/login", response_b.headers["Location"])

        # Device A is unaffected.
        response_a = self.client.get("/")
        self.assertEqual(response_a.status_code, 200)

    def test_revoke_all_other_devices(self):
        client_b = self.app.test_client()
        client_c = self.app.test_client()
        self.login()
        self.login(client=client_b)
        self.login(client=client_c)

        response = self.post_form(
            "/auth/security/sessions/revoke-others",
            {},
            page="/auth/security",
            follow_redirects=True,
        )
        self.assertIn("Signed out of 2 other session(s).", response.get_data(as_text=True))

        self.assertEqual(
            UserSession.query.filter_by(user_id=self.user.id, revoked_at=None).count(), 1
        )
        self.assertEqual(client_b.get("/").status_code, 302)
        self.assertEqual(client_c.get("/").status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_idle_timeout_expires_the_session(self):
        self.login()
        jti = self._current_jti()
        row = db.session.get(UserSession, jti)
        idle_minutes = self.app.config["BLOGG_SESSION_IDLE_MINUTES"]
        row.last_seen_at = utc_now() - timedelta(minutes=idle_minutes + 5)
        db.session.add(row)
        db.session.commit()

        response = self.client.get("/", follow_redirects=True)
        self.assertIn("Your session has expired.", response.get_data(as_text=True))

        db.session.refresh(row)
        self.assertIsNotNone(row.revoked_at)
        self.assertEqual(
            UserSession.query.filter_by(user_id=self.user.id, revoked_at=None).count(), 0
        )

    def test_absolute_timeout_expires_the_session(self):
        self.login()
        jti = self._current_jti()
        row = db.session.get(UserSession, jti)
        row.expires_at = utc_now() - timedelta(hours=1)
        db.session.add(row)
        db.session.commit()

        response = self.client.get("/", follow_redirects=True)
        self.assertIn("Your session has expired.", response.get_data(as_text=True))
        db.session.refresh(row)
        self.assertIsNotNone(row.revoked_at)

    def test_logout_revokes_the_session(self):
        self.login()
        jti = self._current_jti()
        self.logout()
        row = db.session.get(UserSession, jti)
        self.assertIsNotNone(row.revoked_at)
        self.assertIsNotNone(
            AuditEvent.query.filter_by(event=Event.SESSION_REVOKED, actor_id=self.user.id).first()
        )

    def test_cannot_revoke_another_users_session(self):
        other = self.make_user(email="other@example.com", username="other")
        client_other = self.app.test_client()
        self.login(email=other.email, client=client_other)
        other_jti = self._current_jti(client=client_other)

        self.login()
        response = self.post_form(
            f"/auth/security/sessions/{other_jti}/revoke",
            {},
            page="/auth/security",
            follow_redirects=True,
        )
        self.assertIn("Session not found.", response.get_data(as_text=True))
        row = db.session.get(UserSession, other_jti)
        self.assertIsNone(row.revoked_at)
