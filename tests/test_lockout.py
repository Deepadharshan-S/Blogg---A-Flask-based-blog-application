"""Brute-force lockout, account disable and login-history tests."""

from app import db
from app.models import AuditEvent, User
from app.security import Event
from tests.iam_base import IAMTestCase


class LockoutTestCase(IAMTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.make_user()

    def _failed_login(self):
        return self.post_form("/auth/login", {"email": self.user.email, "password": "WrongPass1!"})

    def test_lockout_after_max_failures(self):
        max_failures = self.app.config["BLOGG_MAX_FAILED_LOGINS"]
        for _ in range(max_failures):
            response = self._failed_login()
            self.assertIn("Invalid username or password.", response.get_data(as_text=True))

        self.assertTrue(self.user.is_locked)
        self.assertEqual(self.user.failed_login_attempts, max_failures)

        # Even the correct password is rejected while locked.
        response = self.post_form(
            "/auth/login",
            {"email": self.user.email, "password": "Password123!"},
            follow_redirects=True,
        )
        self.assertIn("temporarily locked", response.get_data(as_text=True))

        # Audit trail: one bad-password failure per attempt, plus the
        # correct-password attempt made while locked (also a failed login),
        # plus a single lockout event.
        failures = AuditEvent.query.filter(
            AuditEvent.event == Event.LOGIN_FAILED,
            AuditEvent.actor_id == self.user.id,
            AuditEvent.success.is_(False),
            AuditEvent.detail.like("%bad_password%"),
        ).count()
        self.assertEqual(failures, max_failures)
        locked_attempts = AuditEvent.query.filter(
            AuditEvent.event == Event.LOGIN_FAILED,
            AuditEvent.actor_id == self.user.id,
            AuditEvent.detail.like("%locked%"),
        ).count()
        self.assertEqual(locked_attempts, 1)
        lockouts = AuditEvent.query.filter_by(
            event=Event.LOGIN_LOCKED, actor_id=self.user.id
        ).count()
        self.assertEqual(lockouts, 1)

    def test_failed_login_counter_resets_on_success(self):
        for _ in range(3):
            self._failed_login()
        response = self.login()
        self.assertIn(self.user.username, response.get_data(as_text=True))
        self.assertEqual(self.user.failed_login_attempts, 0)
        self.assertFalse(self.user.is_locked)

    def test_unknown_email_gets_same_generic_error(self):
        """No account enumeration: unknown emails look like bad passwords."""
        response = self.post_form(
            "/auth/login",
            {"email": "ghost@example.com", "password": "whatever"},
            follow_redirects=True,
        )
        self.assertIn("Invalid username or password.", response.get_data(as_text=True))
        event = AuditEvent.query.filter_by(
            event=Event.LOGIN_FAILED, success=False, actor_label="ghost@example.com"
        ).first()
        self.assertIsNotNone(event)
        self.assertEqual(event.actor_id, None)

    def test_disabled_account_cannot_login(self):
        self.user.active = False
        db.session.add(self.user)
        db.session.commit()

        response = self.post_form(
            "/auth/login",
            {"email": self.user.email, "password": "Password123!"},
            follow_redirects=True,
        )
        self.assertIn("disabled", response.get_data(as_text=True))
        self.assertEqual(
            AuditEvent.query.filter_by(
                event=Event.LOGIN_FAILED, actor_id=self.user.id, success=False
            ).count(),
            1,
        )

    def test_admin_unlock_restores_login(self):
        """An administrator can unlock the account from the admin console."""
        max_failures = self.app.config["BLOGG_MAX_FAILED_LOGINS"]
        for _ in range(max_failures):
            self._failed_login()
        self.assertTrue(self.user.is_locked)

        admin = self.make_user(email="root@example.com", username="root", role=self.admin_role())
        self.login(email=admin.email)
        response = self.post_form(
            f"/admin/users/{self.user.id}",
            {"action": "unlock"},
            page=f"/admin/users/{self.user.id}",
            follow_redirects=True,
        )
        self.assertIn("Account unlocked.", response.get_data(as_text=True))
        self.assertFalse(self.user.is_locked)
        self.assertEqual(self.user.failed_login_attempts, 0)

        event = AuditEvent.query.filter_by(event=Event.USER_UNLOCKED, actor_id=admin.id).first()
        self.assertIsNotNone(event)
        self.assertEqual(event.target_id, self.user.id)

        # The owner can log in again.
        self.logout()
        response = self.login()
        self.assertIn(self.user.username, response.get_data(as_text=True))

    def test_login_history_is_recorded(self):
        response = self.login()
        self.assertIn(self.user.username, response.get_data(as_text=True))
        user = db.session.get(User, self.user.id)
        self.assertIsNotNone(user.last_login_at)

        success = AuditEvent.query.filter_by(
            event=Event.LOGIN_SUCCESS, actor_id=self.user.id
        ).first()
        self.assertIsNotNone(success)
        self.assertEqual(success.ip, "127.0.0.1")
