import re
import unittest
from unittest.mock import patch

from app import create_app, db
from app.models import Role, User


class AuthRoutesTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        Role.insert_roles()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def _get_csrf_token(self):
        response = self.client.get("/auth/login")
        match = re.search(
            r'<meta name="csrf-token" content="([^"]+)">', response.get_data(as_text=True)
        )
        if not match:
            match = re.search(
                r'name="csrf_token"[^>]*value="([^"]+)"', response.get_data(as_text=True)
            )
        self.assertTrue(match, "Could not extract CSRF token")
        return match.group(1)

    def _login(self, email, password):
        token = self._get_csrf_token()
        return self.client.post(
            "/auth/login",
            headers={"X-CSRFToken": token},
            data={"email": email, "password": password},
            follow_redirects=True,
        )

    @patch("app.auth.views.send_email")
    def test_registration_success(self, mock_send_email):
        """Ensure a user can register with valid details and an email is dispatched."""
        token = self._get_csrf_token()
        response = self.client.post(
            "/auth/register",
            headers={"X-CSRFToken": token},
            data={
                "email": "newuser@example.com",
                "username": "newuser",
                "password": "Password123!",
                "password2": "Password123!",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)

        user = User.query.filter_by(email="newuser@example.com").first()
        self.assertIsNotNone(user)
        self.assertEqual(user.username, "newuser")
        self.assertFalse(user.confirmed)
        self.assertTrue(user.verify_password("Password123!"))
        mock_send_email.assert_called_once()

    def test_registration_validation_errors(self):
        """Ensure duplicate credentials and weak passwords are rejected."""
        # Pre-seed existing user
        existing = User(
            email="existing@example.com",
            username="existing",
            password="Password123!",
            confirmed=True,
        )
        db.session.add(existing)
        db.session.commit()

        token = self._get_csrf_token()

        # 1. Duplicate email
        res1 = self.client.post(
            "/auth/register",
            headers={"X-CSRFToken": token},
            data={
                "email": "existing@example.com",
                "username": "unique1",
                "password": "Password123!",
                "password2": "Password123!",
            },
        )
        self.assertIn("Email already registered.", res1.get_data(as_text=True))

        # 2. Duplicate username
        res2 = self.client.post(
            "/auth/register",
            headers={"X-CSRFToken": token},
            data={
                "email": "unique@example.com",
                "username": "existing",
                "password": "Password123!",
                "password2": "Password123!",
            },
        )
        self.assertIn("Username already in use.", res2.get_data(as_text=True))

        # 3. Weak password (too short, no special char, no digit)
        weak_passwords = [
            "short",
            "nouppercase123!",
            "NOLOWERCASE123!",
            "NoSpecialChar123",
            "NoDigits!abc",
        ]
        for weak in weak_passwords:
            res_weak = self.client.post(
                "/auth/register",
                headers={"X-CSRFToken": token},
                data={
                    "email": f"weak_{weak[:5]}@example.com",
                    "username": f"weak_{weak[:5]}",
                    "password": weak,
                    "password2": weak,
                },
            )
            self.assertIn("Password must", res_weak.get_data(as_text=True))

    def test_login_and_logout_flow(self):
        """Ensure valid login logs in the user and logout clears the session."""
        user = User(
            email="login@example.com",
            username="loginuser",
            password="Password123!",
            confirmed=True,
        )
        db.session.add(user)
        db.session.commit()

        # Invalid password
        res_fail = self._login("login@example.com", "WrongPassword!")
        self.assertIn("Invalid username or password.", res_fail.get_data(as_text=True))

        # Valid login
        res_success = self._login("login@example.com", "Password123!")
        self.assertEqual(res_success.status_code, 200)
        self.assertIn("loginuser", res_success.get_data(as_text=True))

        # Logout
        res_logout = self.client.get("/auth/logout", follow_redirects=True)
        self.assertEqual(res_logout.status_code, 200)
        self.assertIn("You have been logged out.", res_logout.get_data(as_text=True))

    def test_unconfirmed_account_restriction_and_confirmation(self):
        """Ensure unconfirmed users are redirected to unconfirmed page until confirmed."""
        user = User(
            email="unconf@example.com",
            username="unconf",
            password="Password123!",
            confirmed=False,
        )
        db.session.add(user)
        db.session.commit()

        # Login as unconfirmed user
        self._login("unconf@example.com", "Password123!")

        # Accessing home page redirects to unconfirmed notice
        res_index = self.client.get("/", follow_redirects=True)
        self.assertIn("Your account is not confirmed yet.", res_index.get_data(as_text=True))

        # Invalid token while unconfirmed yields warning
        res_invalid = self.client.get("/auth/confirm/bad-token", follow_redirects=True)
        self.assertIn(
            "The confirmation link is invalid or has expired.", res_invalid.get_data(as_text=True)
        )
        db.session.refresh(user)
        self.assertFalse(user.confirmed)

        # Confirm account with valid token
        confirm_token = user.generate_confirmation_token()
        res_confirm = self.client.get(f"/auth/confirm/{confirm_token}", follow_redirects=True)
        self.assertEqual(res_confirm.status_code, 200)
        self.assertIn(
            "You have confirmed your account. Thanks!", res_confirm.get_data(as_text=True)
        )

        db.session.refresh(user)
        self.assertTrue(user.confirmed)

    @patch("app.auth.views.send_email")
    def test_resend_confirmation_email(self, mock_send_email):
        """Ensure unconfirmed user can request a new confirmation email."""
        user = User(
            email="resend@example.com",
            username="resenduser",
            password="Password123!",
            confirmed=False,
        )
        db.session.add(user)
        db.session.commit()

        self._login("resend@example.com", "Password123!")

        res = self.client.get("/auth/confirm", follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("A new confirmation email has been sent", res.get_data(as_text=True))
        mock_send_email.assert_called_once()

    def test_change_password_flow(self):
        """Ensure authenticated user can update their password."""
        user = User(
            email="pwchange@example.com",
            username="pwchange",
            password="OldPassword123!",
            confirmed=True,
        )
        db.session.add(user)
        db.session.commit()

        self._login("pwchange@example.com", "OldPassword123!")
        token = self._get_csrf_token()

        # Wrong old password
        res_wrong = self.client.post(
            "/auth/change-password",
            headers={"X-CSRFToken": token},
            data={
                "old_password": "IncorrectPassword!",
                "password": "NewPassword123!",
                "password2": "NewPassword123!",
            },
            follow_redirects=True,
        )
        self.assertIn("Invalid password.", res_wrong.get_data(as_text=True))

        # Correct old password
        res_correct = self.client.post(
            "/auth/change-password",
            headers={"X-CSRFToken": token},
            data={
                "old_password": "OldPassword123!",
                "password": "NewPassword123!",
                "password2": "NewPassword123!",
            },
            follow_redirects=True,
        )
        self.assertEqual(res_correct.status_code, 200)
        self.assertIn("Your password has been updated.", res_correct.get_data(as_text=True))

        db.session.refresh(user)
        self.assertTrue(user.verify_password("NewPassword123!"))

    @patch("app.auth.views.send_email")
    def test_change_email_flow(self, mock_send_email):
        """Ensure email change request and confirmation update the user's email."""
        user = User(
            email="original@example.com",
            username="emailchanger",
            password="Password123!",
            confirmed=True,
        )
        db.session.add(user)
        db.session.commit()

        self._login("original@example.com", "Password123!")
        token = self._get_csrf_token()

        # Request email change
        res_req = self.client.post(
            "/auth/change_email",
            headers={"X-CSRFToken": token},
            data={"email": "new_address@example.com", "password": "Password123!"},
            follow_redirects=True,
        )
        self.assertEqual(res_req.status_code, 200)
        self.assertIn(
            "instructions to confirm your new email address", res_req.get_data(as_text=True)
        )
        mock_send_email.assert_called_once()

        # Confirm new email with generated token
        change_token = user.generate_email_change_token("new_address@example.com")
        res_conf = self.client.get(f"/auth/change_email/{change_token}", follow_redirects=True)
        self.assertEqual(res_conf.status_code, 200)
        self.assertIn("Your email address has been updated.", res_conf.get_data(as_text=True))

        db.session.refresh(user)
        self.assertEqual(user.email, "new_address@example.com")

    @patch("app.auth.views.send_email")
    def test_password_reset_request_registered_user(self, mock_send_email):
        """Ensure requesting password reset for registered email sends reset email."""
        user = User(
            email="resetreq@example.com",
            username="resetreq",
            password="Password123!",
            confirmed=True,
        )
        db.session.add(user)
        db.session.commit()

        csrf_token = self._get_csrf_token()
        res = self.client.post(
            "/auth/reset",
            headers={"X-CSRFToken": csrf_token},
            data={"email": "resetreq@example.com"},
            follow_redirects=True,
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn(
            "An email with instructions to reset your password has been sent to you.",
            res.get_data(as_text=True),
        )
        mock_send_email.assert_called_once()
        args, kwargs = mock_send_email.call_args
        self.assertEqual(args[0], "resetreq@example.com")
        self.assertEqual(args[1], "Reset Your Password")
        self.assertEqual(args[2], "auth/email/reset_password")
        self.assertIn("token", kwargs)
        self.assertEqual(kwargs["user"], user)

    @patch("app.auth.views.send_email")
    def test_password_reset_request_unregistered_user_identical_response(self, mock_send_email):
        """Ensure requesting reset for unregistered email returns identical response (enumeration defense)."""
        csrf_token = self._get_csrf_token()
        res = self.client.post(
            "/auth/reset",
            headers={"X-CSRFToken": csrf_token},
            data={"email": "nonexistent@example.com"},
            follow_redirects=True,
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn(
            "An email with instructions to reset your password has been sent to you.",
            res.get_data(as_text=True),
        )
        mock_send_email.assert_not_called()

    def test_password_reset_get_renders_form(self):
        """Ensure visiting password reset link with a valid token renders the form."""
        user = User(
            email="getreset@example.com",
            username="getreset",
            password="Password123!",
            confirmed=True,
        )
        db.session.add(user)
        db.session.commit()

        reset_token = user.generate_reset_token()
        res = self.client.get(f"/auth/reset/{reset_token}")
        self.assertEqual(res.status_code, 200)
        self.assertIn("Reset Password", res.get_data(as_text=True))
        self.assertIn('name="password"', res.get_data(as_text=True))

    def test_password_reset_post_success_and_replay_prevention(self):
        """Ensure password reset succeeds, updates password, and prevents token replay."""
        user = User(
            email="succreset@example.com",
            username="succreset",
            password="OldPassword123!",
            confirmed=True,
        )
        db.session.add(user)
        db.session.commit()

        reset_token = user.generate_reset_token()
        csrf_token = self._get_csrf_token()

        # Submit valid new password
        res = self.client.post(
            f"/auth/reset/{reset_token}",
            headers={"X-CSRFToken": csrf_token},
            data={"password": "NewPassword123!", "password2": "NewPassword123!"},
            follow_redirects=True,
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("Your password has been updated.", res.get_data(as_text=True))

        db.session.refresh(user)
        self.assertTrue(user.verify_password("NewPassword123!"))
        self.assertFalse(user.verify_password("OldPassword123!"))

        # Replay: Submitting the same token again must fail and redirect gracefully
        replay_token = self._get_csrf_token()
        res_replay = self.client.post(
            f"/auth/reset/{reset_token}",
            headers={"X-CSRFToken": replay_token},
            data={"password": "AnotherPassword123!", "password2": "AnotherPassword123!"},
            follow_redirects=True,
        )
        self.assertEqual(res_replay.status_code, 200)
        self.assertIn(
            "The password reset link is invalid or has expired.", res_replay.get_data(as_text=True)
        )
        db.session.refresh(user)
        self.assertTrue(user.verify_password("NewPassword123!"))

    def test_password_reset_invalid_or_expired_token(self):
        """Ensure invalid or expired tokens are handled cleanly without HTTP 500."""
        # 1. GET with invalid token does not crash
        res_get = self.client.get("/auth/reset/invalid-reset-token")
        self.assertEqual(res_get.status_code, 200)

        # 2. POST with invalid token safely redirects with error flash
        csrf_token = self._get_csrf_token()
        res_post = self.client.post(
            "/auth/reset/invalid-reset-token",
            headers={"X-CSRFToken": csrf_token},
            data={"password": "NewPassword123!", "password2": "NewPassword123!"},
            follow_redirects=True,
        )
        self.assertEqual(res_post.status_code, 200)
        self.assertIn(
            "The password reset link is invalid or has expired.", res_post.get_data(as_text=True)
        )

    def test_password_reset_validation_errors(self):
        """Ensure mismatched or weak passwords in reset form are rejected without modifying password."""
        user = User(
            email="pwval@example.com",
            username="pwval",
            password="OriginalPassword123!",
            confirmed=True,
        )
        db.session.add(user)
        db.session.commit()

        reset_token = user.generate_reset_token()
        csrf_token = self._get_csrf_token()

        # Mismatched passwords
        res_mismatch = self.client.post(
            f"/auth/reset/{reset_token}",
            headers={"X-CSRFToken": csrf_token},
            data={"password": "NewPassword123!", "password2": "MismatchPassword123!"},
        )
        self.assertEqual(res_mismatch.status_code, 200)
        self.assertIn("Passwords must match", res_mismatch.get_data(as_text=True))

        # Weak password
        res_weak = self.client.post(
            f"/auth/reset/{reset_token}",
            headers={"X-CSRFToken": csrf_token},
            data={"password": "short", "password2": "short"},
        )
        self.assertEqual(res_weak.status_code, 200)
        self.assertIn("Password must", res_weak.get_data(as_text=True))

        db.session.refresh(user)
        self.assertTrue(user.verify_password("OriginalPassword123!"))

    def test_password_reset_csrf_protection(self):
        """Ensure CSRF is enforced on password reset POST endpoints."""
        # Reset request POST without CSRF token
        res_req = self.client.post(
            "/auth/reset",
            data={"email": "any@example.com"},
        )
        self.assertEqual(res_req.status_code, 400)

        # Reset submit POST without CSRF token
        res_submit = self.client.post(
            "/auth/reset/anytoken",
            data={"password": "NewPassword123!", "password2": "NewPassword123!"},
        )
        self.assertEqual(res_submit.status_code, 400)
