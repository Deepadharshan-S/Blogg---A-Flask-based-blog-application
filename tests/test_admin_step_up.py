"""BLOGG-SEC-018: Administrative Step-Up Authentication tests.

Verifies:
1. Re-authentication is required before sensitive administrative operations
   (account tombstoning, role modifications, custom role lifecycle).
2. Verification checks the authenticated administrator's password, never the target's.
3. Target user's password is strictly rejected when supplied by the administrator.
4. Incorrect passwords fail safely and log an audit event.
5. Successful step-up grants a short-lived authorization window bound to the admin and session JTI.
6. Authorization expires after the configured timeout (BLOGG_ADMIN_STEP_UP_TIMEOUT).
7. Non-administrators and unauthenticated callers cannot access or bypass step-up.
8. CSRF protection and open-redirect protections are enforced on step-up endpoints.
"""

import json
from unittest.mock import patch

from app import db
from app.models import AuditEvent, Role
from app.security import Event, is_admin_step_up_valid
from tests.iam_base import IAMTestCase


class AdminStepUpTestCase(IAMTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_user(
            email="root_stepup@example.com",
            username="root_stepup",
            password="AdminPassword123!",
            role=self.admin_role(),
        )
        self.target = self.make_user(
            email="target_stepup@example.com",
            username="target_stepup",
            password="TargetPassword123!",
        )
        self.mod_role = Role.query.filter_by(name="Moderator").first()
        self.user_role = Role.query.filter_by(name="User").first()

    # ------------------------------------------------------------------
    # Step-Up Route Access Control & Validation
    # ------------------------------------------------------------------

    def test_step_up_route_requires_authentication(self):
        """Anonymous callers are redirected to login."""
        response = self.client.get("/admin/step-up")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/login", response.headers["Location"])

    def test_step_up_route_denied_to_regular_users(self):
        """Regular users without administrative permissions receive 403 Forbidden."""
        self.login(email=self.target.email, password="TargetPassword123!")
        response = self.client.get("/admin/step-up")
        self.assertEqual(response.status_code, 403)

    def test_step_up_route_renders_for_administrator(self):
        """Administrators can view the step-up challenge page."""
        self.login(email=self.admin.email, password="AdminPassword123!")
        response = self.client.get("/admin/step-up")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Administrative Step-Up Authentication", response.get_data(as_text=True))

    def test_step_up_success_records_audit_and_sets_valid_state(self):
        """Entering the administrator's password confirms step-up and records audit."""
        self.login(email=self.admin.email, password="AdminPassword123!")

        with self.client:
            self.client.get("/admin/")
            self.assertFalse(is_admin_step_up_valid())

            response = self.post_form(
                "/admin/step-up?next=/admin/users",
                {"password": "AdminPassword123!"},
                page="/admin/step-up?next=/admin/users",
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 302)
            self.assertIn("/admin/users", response.headers["Location"])
            self.assertTrue(is_admin_step_up_valid())

        # Audit event recorded
        event = AuditEvent.query.filter_by(
            event=Event.ADMIN_STEP_UP_SUCCESS, actor_id=self.admin.id
        ).first()
        self.assertIsNotNone(event)
        self.assertTrue(event.success)

    def test_step_up_failure_records_audit_and_returns_401(self):
        """Submitting an invalid administrator password returns 401 and logs failure."""
        self.login(email=self.admin.email, password="AdminPassword123!")

        with self.client:
            response = self.post_form(
                "/admin/step-up",
                {"password": "WrongAdminPassword!"},
                page="/admin/step-up",
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 401)
            self.assertFalse(is_admin_step_up_valid())

        event = AuditEvent.query.filter_by(
            event=Event.ADMIN_STEP_UP_FAILED, actor_id=self.admin.id
        ).first()
        self.assertIsNotNone(event)
        self.assertFalse(event.success)

    def test_step_up_open_redirect_mitigation(self):
        """Redirect destinations are validated; off-site redirects default to dashboard."""
        self.login(email=self.admin.email, password="AdminPassword123!")
        response = self.post_form(
            "/admin/step-up?next=https://attacker.example.com/steal",
            {"password": "AdminPassword123!"},
            page="/admin/step-up",
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/admin/")

    # ------------------------------------------------------------------
    # Step-Up Enforcement on High-Impact Operations
    # ------------------------------------------------------------------

    def test_tombstone_account_rejected_without_step_up(self):
        """Account deletion without step-up is redirected to step-up prompt."""
        self.login(email=self.admin.email, password="AdminPassword123!")
        response = self.post_form(
            f"/admin/users/{self.target.id}",
            {"action": "delete_user"},
            page=f"/admin/users/{self.target.id}",
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/admin/step-up", response.headers["Location"])

        # Target account remains active and undeleted
        db.session.refresh(self.target)
        self.assertIsNone(self.target.deleted_at)

    def test_tombstone_account_with_inline_password(self):
        """Account deletion succeeds when valid admin password is provided."""
        self.login(email=self.admin.email, password="AdminPassword123!")
        response = self.post_form(
            f"/admin/users/{self.target.id}",
            {"action": "delete_user", "admin_password": "AdminPassword123!"},
            page=f"/admin/users/{self.target.id}",
            follow_redirects=True,
        )
        self.assertIn("Account deleted", response.get_data(as_text=True))
        db.session.refresh(self.target)
        self.assertIsNotNone(self.target.deleted_at)

    def test_tombstone_account_rejects_target_user_password(self):
        """Target user's password must NEVER be accepted for administrative step-up."""
        self.login(email=self.admin.email, password="AdminPassword123!")
        response = self.post_form(
            f"/admin/users/{self.target.id}",
            {"action": "delete_user", "admin_password": "TargetPassword123!"},
            page=f"/admin/users/{self.target.id}",
            follow_redirects=True,
        )
        self.assertIn("Administrator password verification failed", response.get_data(as_text=True))
        db.session.refresh(self.target)
        self.assertIsNone(self.target.deleted_at)

    def test_role_modification_rejected_without_step_up(self):
        """Role modification without step-up redirects to step-up prompt."""
        self.login(email=self.admin.email, password="AdminPassword123!")
        response = self.post_form(
            f"/admin/users/{self.target.id}",
            {"action": "role", "role_id": self.mod_role.id},
            page=f"/admin/users/{self.target.id}",
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/admin/step-up", response.headers["Location"])

        db.session.refresh(self.target)
        self.assertEqual(self.target.role.name, "User")

    def test_role_modification_succeeds_with_step_up_session(self):
        """Role modification succeeds when administrator has completed step-up."""
        self.login(email=self.admin.email, password="AdminPassword123!")
        self.step_up_admin(password="AdminPassword123!")

        response = self.post_form(
            f"/admin/users/{self.target.id}",
            {"action": "role", "role_id": self.mod_role.id},
            page=f"/admin/users/{self.target.id}",
            follow_redirects=True,
        )
        self.assertIn("is now Moderator.", response.get_data(as_text=True))
        db.session.refresh(self.target)
        self.assertEqual(self.target.role.name, "Moderator")

    def test_step_up_state_expires_after_timeout(self):
        """Step-up elevation expires after BLOGG_ADMIN_STEP_UP_TIMEOUT seconds."""
        self.login(email=self.admin.email, password="AdminPassword123!")
        self.step_up_admin(password="AdminPassword123!")

        with self.client:
            self.client.get("/admin/")
            self.assertTrue(is_admin_step_up_valid())

            # Fast-forward time past 300-second default timeout
            import time

            real_time = time.time()
            with patch("time.time", return_value=real_time + 305):
                self.assertFalse(is_admin_step_up_valid())

                # Attempting operation with expired step-up is redirected
                response = self.post_form(
                    f"/admin/users/{self.target.id}",
                    {"action": "role", "role_id": self.mod_role.id},
                    page=f"/admin/users/{self.target.id}",
                    follow_redirects=False,
                )
                self.assertEqual(response.status_code, 302)
                self.assertIn("/admin/step-up", response.headers["Location"])

        db.session.refresh(self.target)
        self.assertEqual(self.target.role.name, "User")

    def test_custom_role_lifecycle_step_up(self):
        """Creating and deleting custom roles requires administrator step-up."""
        self.login(email=self.admin.email, password="AdminPassword123!")

        # 1. Creation without step-up fails
        response = self.post_form(
            "/admin/roles/new",
            {"name": "AuditorRole", "view_audit": "y"},
            page="/admin/roles/new",
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/admin/step-up", response.headers["Location"])
        self.assertIsNone(Role.query.filter_by(name="AuditorRole").first())

        # 2. Creation with inline admin_password succeeds
        response = self.post_form(
            "/admin/roles/new",
            {"name": "AuditorRole", "view_audit": "y", "admin_password": "AdminPassword123!"},
            page="/admin/roles/new",
            follow_redirects=True,
        )
        self.assertIn("Role 'AuditorRole' created.", self.page_text(response))
        new_role = Role.query.filter_by(name="AuditorRole").first()
        self.assertIsNotNone(new_role)

        # 3. Deletion with step-up succeeds
        response = self.post_form(
            f"/admin/roles/{new_role.id}/delete",
            {"admin_password": "AdminPassword123!"},
            page="/admin/roles",
            follow_redirects=True,
        )
        self.assertIn("Role 'AuditorRole' deleted.", self.page_text(response))
        self.assertIsNone(db.session.get(Role, new_role.id))

    # ------------------------------------------------------------------
    # SEC-ASSESS-003: MFA-Aware Administrative Step-Up Tests
    # ------------------------------------------------------------------

    def test_mfa_admin_step_up_success_with_valid_totp(self):
        """MFA-enrolled admin providing both password and valid TOTP code succeeds."""
        import pyotp

        secret = self.admin.generate_mfa_secret()
        self.admin.mfa_enabled = True
        db.session.add(self.admin)
        db.session.commit()

        self.login(
            email=self.admin.email, password="AdminPassword123!", otp=pyotp.TOTP(secret).now()
        )

        with self.client:
            self.client.get("/admin/")
            self.assertFalse(is_admin_step_up_valid())

            totp_code = pyotp.TOTP(secret).now()
            response = self.post_form(
                "/admin/step-up?next=/admin/users",
                {"password": "AdminPassword123!", "otp": totp_code},
                page="/admin/step-up?next=/admin/users",
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 302)
            self.assertIn("/admin/users", response.headers["Location"])
            self.assertTrue(is_admin_step_up_valid())

        event = (
            AuditEvent.query.filter_by(event=Event.ADMIN_STEP_UP_SUCCESS, actor_id=self.admin.id)
            .order_by(AuditEvent.id.desc())
            .first()
        )
        self.assertIsNotNone(event)
        self.assertTrue(event.success)
        detail = json.loads(event.detail or "{}")
        self.assertTrue(detail.get("mfa_verified"))

    def test_mfa_admin_step_up_fails_with_missing_totp(self):
        """MFA-enrolled admin providing valid password but omitting TOTP is rejected with 401."""
        import pyotp

        secret = self.admin.generate_mfa_secret()
        self.admin.mfa_enabled = True
        db.session.add(self.admin)
        db.session.commit()

        self.login(
            email=self.admin.email, password="AdminPassword123!", otp=pyotp.TOTP(secret).now()
        )

        with self.client:
            response = self.post_form(
                "/admin/step-up",
                {"password": "AdminPassword123!"},
                page="/admin/step-up",
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 401)
            self.assertFalse(is_admin_step_up_valid())

        event = (
            AuditEvent.query.filter_by(event=Event.ADMIN_STEP_UP_FAILED, actor_id=self.admin.id)
            .order_by(AuditEvent.id.desc())
            .first()
        )
        self.assertIsNotNone(event)
        detail = json.loads(event.detail or "{}")
        self.assertEqual(detail.get("reason"), "incorrect_totp")

    def test_mfa_admin_step_up_fails_with_incorrect_totp(self):
        """MFA-enrolled admin providing valid password but invalid TOTP is rejected with 401."""
        import pyotp

        secret = self.admin.generate_mfa_secret()
        self.admin.mfa_enabled = True
        db.session.add(self.admin)
        db.session.commit()

        self.login(
            email=self.admin.email, password="AdminPassword123!", otp=pyotp.TOTP(secret).now()
        )

        with self.client:
            response = self.post_form(
                "/admin/step-up",
                {"password": "AdminPassword123!", "otp": "000000"},
                page="/admin/step-up",
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 401)
            self.assertFalse(is_admin_step_up_valid())

        event = (
            AuditEvent.query.filter_by(event=Event.ADMIN_STEP_UP_FAILED, actor_id=self.admin.id)
            .order_by(AuditEvent.id.desc())
            .first()
        )
        self.assertIsNotNone(event)
        detail = json.loads(event.detail or "{}")
        self.assertEqual(detail.get("reason"), "incorrect_totp")

    def test_mfa_admin_step_up_fails_with_incorrect_password(self):
        """MFA-enrolled admin providing invalid password with valid TOTP is rejected with 401."""
        import pyotp

        secret = self.admin.generate_mfa_secret()
        self.admin.mfa_enabled = True
        db.session.add(self.admin)
        db.session.commit()

        self.login(
            email=self.admin.email, password="AdminPassword123!", otp=pyotp.TOTP(secret).now()
        )

        with self.client:
            totp_code = pyotp.TOTP(secret).now()
            response = self.post_form(
                "/admin/step-up",
                {"password": "WrongPassword!", "otp": totp_code},
                page="/admin/step-up",
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 401)
            self.assertFalse(is_admin_step_up_valid())

        event = (
            AuditEvent.query.filter_by(event=Event.ADMIN_STEP_UP_FAILED, actor_id=self.admin.id)
            .order_by(AuditEvent.id.desc())
            .first()
        )
        self.assertIsNotNone(event)
        detail = json.loads(event.detail or "{}")
        self.assertEqual(detail.get("reason"), "incorrect_password")

    def test_mfa_admin_step_up_fails_with_expired_totp(self):
        """MFA-enrolled admin providing an expired TOTP code is rejected."""
        import time

        import pyotp

        secret = self.admin.generate_mfa_secret()
        self.admin.mfa_enabled = True
        db.session.add(self.admin)
        db.session.commit()

        self.login(
            email=self.admin.email, password="AdminPassword123!", otp=pyotp.TOTP(secret).now()
        )

        # Generate TOTP code from 5 minutes (300 seconds) ago
        expired_totp = pyotp.TOTP(secret).at(time.time() - 300)

        with self.client:
            response = self.post_form(
                "/admin/step-up",
                {"password": "AdminPassword123!", "otp": expired_totp},
                page="/admin/step-up",
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 401)
            self.assertFalse(is_admin_step_up_valid())

    def test_mfa_admin_step_up_succeeds_with_backup_code(self):
        """MFA-enrolled admin can use an unconsumed backup code for step-up."""
        import pyotp

        secret = self.admin.generate_mfa_secret()
        self.admin.mfa_enabled = True
        codes = self.admin.generate_backup_codes(total=2)
        db.session.add(self.admin)
        db.session.commit()

        self.login(
            email=self.admin.email, password="AdminPassword123!", otp=pyotp.TOTP(secret).now()
        )

        backup_code = codes[0]

        with self.client:
            response = self.post_form(
                "/admin/step-up",
                {"password": "AdminPassword123!", "otp": backup_code},
                page="/admin/step-up",
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 302)
            self.assertTrue(is_admin_step_up_valid())

        # Backup code is consumed; reusing it fails
        db.session.refresh(self.admin)
        self.assertFalse(self.admin.consume_backup_code(backup_code))

    def test_mfa_admin_step_up_rejects_target_user_credentials_and_totp(self):
        """Target user's password or TOTP cannot satisfy admin step-up."""
        import pyotp

        secret_admin = self.admin.generate_mfa_secret()
        self.admin.mfa_enabled = True

        secret_target = self.target.generate_mfa_secret()
        self.target.mfa_enabled = True
        db.session.add_all([self.admin, self.target])
        db.session.commit()

        self.login(
            email=self.admin.email, password="AdminPassword123!", otp=pyotp.TOTP(secret_admin).now()
        )

        target_totp = pyotp.TOTP(secret_target).now()
        admin_totp = pyotp.TOTP(secret_admin).now()

        with self.client:
            # 1. Target password + Admin TOTP -> Fails
            res1 = self.post_form(
                "/admin/step-up",
                {"password": "TargetPassword123!", "otp": admin_totp},
                page="/admin/step-up",
                follow_redirects=False,
            )
            self.assertEqual(res1.status_code, 401)

            # 2. Admin password + Target TOTP -> Fails
            res2 = self.post_form(
                "/admin/step-up",
                {"password": "AdminPassword123!", "otp": target_totp},
                page="/admin/step-up",
                follow_redirects=False,
            )
            self.assertEqual(res2.status_code, 401)

            # 3. Target password + Target TOTP -> Fails
            res3 = self.post_form(
                "/admin/step-up",
                {"password": "TargetPassword123!", "otp": target_totp},
                page="/admin/step-up",
                follow_redirects=False,
            )
            self.assertEqual(res3.status_code, 401)

    def test_disabled_mfa_admin_step_up_requires_only_password(self):
        """Admin without MFA enabled requires only password and succeeds without OTP."""
        self.admin.mfa_enabled = False
        db.session.add(self.admin)
        db.session.commit()

        self.login(email=self.admin.email, password="AdminPassword123!")

        with self.client:
            response = self.post_form(
                "/admin/step-up",
                {"password": "AdminPassword123!"},
                page="/admin/step-up",
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 302)
            self.assertTrue(is_admin_step_up_valid())

        event = (
            AuditEvent.query.filter_by(event=Event.ADMIN_STEP_UP_SUCCESS, actor_id=self.admin.id)
            .order_by(AuditEvent.id.desc())
            .first()
        )
        self.assertIsNotNone(event)
        detail = json.loads(event.detail or "{}")
        self.assertFalse(detail.get("mfa_verified"))
