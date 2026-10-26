import re
import unittest
from unittest.mock import patch

from flask import g

from app import create_app, db, limiter
from app.auth.views import is_safe_url
from app.models import Role, User


class AuthRoutesTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()

        # The app context pushed above is reused by every request Flask
        # serves, so `g` (flask-wtf caches the CSRF token there, flask-login
        # the current user) would leak between requests. Clear it after each
        # request to restore production-like per-request isolation — the
        # same fix as tests/iam_base.py. Without it a stale g.csrf_token
        # short-circuits generate_csrf() after logout, the session never
        # gets a fresh csrf_token and the emptied session deletes its cookie.
        @self.app.teardown_request
        def _isolate_g(err=None):  # noqa: ARG001
            g.pop("csrf_token", None)
            g.pop("_login_user", None)

        db.create_all()
        Role.insert_roles()
        limiter.reset()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def _get_csrf_token(self):
        # follow_redirects: unconfirmed users are bounced from "/" to
        # /auth/unconfirmed, which still carries the csrf meta tag.
        response = self.client.get("/", follow_redirects=True)
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

        # Logout (POST-only; a GET would be forged cross-site)
        token = self._get_csrf_token()
        res_logout = self.client.post(
            "/auth/logout",
            headers={"X-CSRFToken": token},
            data={"csrf_token": token},
            follow_redirects=True,
        )
        self.assertEqual(res_logout.status_code, 200)
        self.assertIn("You have been logged out.", res_logout.get_data(as_text=True))
        self.assertEqual(self.client.get("/auth/logout").status_code, 405)

    def test_login_redirect_validation(self):
        """Ensure login next parameter permits safe local paths and rejects external/malformed URLs."""
        # Unit verification of is_safe_url
        self.assertTrue(is_safe_url("/user/profile"))
        self.assertTrue(is_safe_url("/search?q=test&page=2"))
        self.assertTrue(is_safe_url("/"))
        self.assertFalse(is_safe_url("//attacker.example"))
        self.assertFalse(is_safe_url("//attacker.example/phish"))
        self.assertFalse(is_safe_url("https://attacker.example"))
        self.assertFalse(is_safe_url("http://attacker.example"))
        self.assertFalse(is_safe_url("javascript:alert(1)"))
        self.assertFalse(is_safe_url("/\\\\attacker.example"))
        self.assertFalse(is_safe_url("/\\evil.com"))
        self.assertFalse(is_safe_url("\\\\evil.com"))
        self.assertFalse(is_safe_url(""))
        self.assertFalse(is_safe_url(None))
        self.assertFalse(is_safe_url("   "))
        self.assertFalse(is_safe_url("evil.com"))

        user = User(
            email="redir@example.com",
            username="rediruser",
            password="Password123!",
            confirmed=True,
        )
        db.session.add(user)
        db.session.commit()

        # 1. Valid local path
        limiter.reset()
        csrf_token = self._get_csrf_token()
        res1 = self.client.post(
            "/auth/login?next=/user/rediruser",
            headers={"X-CSRFToken": csrf_token},
            data={"email": "redir@example.com", "password": "Password123!"},
            follow_redirects=False,
        )
        self.assertEqual(res1.status_code, 302)
        self.assertEqual(res1.headers.get("Location"), "/user/rediruser")

        # 2. Local path with query string
        limiter.reset()
        csrf_token = self._get_csrf_token()
        res2 = self.client.post(
            "/auth/login?next=/search?q=test%26page=2",
            headers={"X-CSRFToken": csrf_token},
            data={"email": "redir@example.com", "password": "Password123!"},
            follow_redirects=False,
        )
        self.assertEqual(res2.status_code, 302)
        self.assertEqual(res2.headers.get("Location"), "/search?q=test&page=2")

        # 3. Protocol-relative URL (rejected -> index fallback)
        limiter.reset()
        csrf_token = self._get_csrf_token()
        res3 = self.client.post(
            "/auth/login?next=//attacker.example/phish",
            headers={"X-CSRFToken": csrf_token},
            data={"email": "redir@example.com", "password": "Password123!"},
            follow_redirects=False,
        )
        self.assertEqual(res3.status_code, 302)
        self.assertEqual(res3.headers.get("Location"), "/")

        # 4. Absolute external URL (rejected -> index fallback)
        limiter.reset()
        csrf_token = self._get_csrf_token()
        res4 = self.client.post(
            "/auth/login?next=https://attacker.example/login",
            headers={"X-CSRFToken": csrf_token},
            data={"email": "redir@example.com", "password": "Password123!"},
            follow_redirects=False,
        )
        self.assertEqual(res4.status_code, 302)
        self.assertEqual(res4.headers.get("Location"), "/")

        # 5. Backslash variants (rejected -> index fallback)
        for bad_next in ["/\\\\attacker.example", "\\\\attacker.example", "/\\evil.com"]:
            limiter.reset()
            csrf_token = self._get_csrf_token()
            res_bad = self.client.post(
                f"/auth/login?next={bad_next}",
                headers={"X-CSRFToken": csrf_token},
                data={"email": "redir@example.com", "password": "Password123!"},
                follow_redirects=False,
            )
            self.assertEqual(res_bad.status_code, 302)
            self.assertEqual(res_bad.headers.get("Location"), "/")

        # 6. Empty and whitespace-only next (fallback to index)
        limiter.reset()
        csrf_token = self._get_csrf_token()
        res_empty = self.client.post(
            "/auth/login?next=",
            headers={"X-CSRFToken": csrf_token},
            data={"email": "redir@example.com", "password": "Password123!"},
            follow_redirects=False,
        )
        self.assertEqual(res_empty.status_code, 302)
        self.assertEqual(res_empty.headers.get("Location"), "/")

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

        # POST-only: a GET must no longer trigger the email.
        res_get = self.client.get("/auth/confirm")
        self.assertEqual(res_get.status_code, 405)
        mock_send_email.assert_not_called()

        token = self._get_csrf_token()
        res = self.client.post(
            "/auth/confirm",
            headers={"X-CSRFToken": token},
            follow_redirects=True,
        )
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

    @patch("app.auth.views.send_email")
    def test_rate_limiting_registration_and_reset(self, mock_send_email):
        """Ensure rate limits are enforced on registration and reset endpoints."""
        limiter.reset()

        # 1. Registration endpoint (10 per hour limit)
        token = self._get_csrf_token()
        for i in range(10):
            res = self.client.post(
                "/auth/register",
                headers={"X-CSRFToken": token},
                data={
                    "email": f"user_rl_{i}@example.com",
                    "username": f"userrl{i}",
                    "password": "Password123!",
                    "password2": "Password123!",
                },
            )
            self.assertEqual(res.status_code, 302)

        # 11th registration attempt must be rate-limited (HTTP 429)
        res_limit = self.client.post(
            "/auth/register",
            headers={"X-CSRFToken": token},
            data={
                "email": "user_rl_exceeded@example.com",
                "username": "userrlexceeded",
                "password": "Password123!",
                "password2": "Password123!",
            },
        )
        self.assertEqual(res_limit.status_code, 429)

        # 2. Password reset endpoint (5 per hour limit)
        limiter.reset()
        reset_token = self._get_csrf_token()
        for i in range(5):
            res = self.client.post(
                "/auth/reset",
                headers={"X-CSRFToken": reset_token},
                data={"email": f"reset_rl_{i}@example.com"},
            )
            self.assertEqual(res.status_code, 302)

        # 6th reset attempt must be rate-limited (HTTP 429)
        res_reset_limit = self.client.post(
            "/auth/reset",
            headers={"X-CSRFToken": reset_token},
            data={"email": "reset_rl_exceeded@example.com"},
        )
        self.assertEqual(res_reset_limit.status_code, 429)

    def test_email_normalization_across_auth_flows(self):
        """BLOGG-SEC-009: Verify email normalization (stripping whitespace and lowercasing) across auth flows."""
        limiter.reset()
        token = self._get_csrf_token()

        # 1. Register with mixed-case and surrounding whitespace
        res_reg = self.client.post(
            "/auth/register",
            headers={"X-CSRFToken": token},
            data={
                "email": "  MixedUser@Example.COM  ",
                "username": "mixeduser",
                "password": "Password123!",
                "password2": "Password123!",
            },
            follow_redirects=False,
        )
        self.assertEqual(res_reg.status_code, 302)

        # Verify user in database has normalized email
        user = User.query.filter_by(username="mixeduser").first()
        self.assertIsNotNone(user)
        self.assertEqual(user.email, "mixeduser@example.com")

        # 2. Duplicate registration with different case/spaces is rejected by validation
        token = self._get_csrf_token()
        res_dup = self.client.post(
            "/auth/register",
            headers={"X-CSRFToken": token},
            data={
                "email": "MIXEDUSER@example.com",
                "username": "anotheruser",
                "password": "Password123!",
                "password2": "Password123!",
            },
            follow_redirects=False,
        )
        self.assertEqual(res_dup.status_code, 200)
        self.assertIn("Email already registered.", res_dup.get_data(as_text=True))

        # 3. Login with mixed-case and whitespace succeeds
        token = self._get_csrf_token()
        res_login = self.client.post(
            "/auth/login",
            headers={"X-CSRFToken": token},
            data={
                "email": "  MIXEDuser@EXAMPLE.com  ",
                "password": "Password123!",
            },
            follow_redirects=False,
        )
        self.assertEqual(res_login.status_code, 302)
        self.assertEqual(res_login.headers.get("Location"), "/")

        # 4. Password reset request with mixed-case email finds the account (as anonymous user)
        # Logout is POST-only; reuse the pre-login CSRF token because an
        # unconfirmed signed-in user is bounced off "/" (auth.before_request),
        # so fetching a fresh token there would fail. The session's csrf_token
        # survives login.
        res_logout = self.client.post(
            "/auth/logout",
            headers={"X-CSRFToken": token},
            data={"csrf_token": token},
        )
        self.assertEqual(res_logout.status_code, 302)
        token = self._get_csrf_token()
        res_reset = self.client.post(
            "/auth/reset",
            headers={"X-CSRFToken": token},
            data={"email": "  MixedUser@Example.COM  "},
            follow_redirects=False,
        )
        self.assertEqual(res_reset.status_code, 302)
        self.assertEqual(res_reset.headers.get("Location"), "/auth/login")
