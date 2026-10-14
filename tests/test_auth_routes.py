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
