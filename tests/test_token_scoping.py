import unittest

from app import create_app, db
from app.models import Role, User


class TokenScopingTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        Role.insert_roles()
        self.client = self.app.test_client()

        # Create unconfirmed test user
        self.user = User(
            email="tokenuser@example.com",
            username="tokenuser",
            password="Password123!",
            confirmed=False,
        )
        db.session.add(self.user)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_confirmation_token_cannot_authenticate_api(self):
        """Ensure an email confirmation token cannot be used to authenticate API requests."""
        confirm_token = self.user.generate_confirmation_token()

        # 1. Direct model validation must reject confirmation token as auth token
        verified_user = User.verify_auth_token(confirm_token)
        self.assertIsNone(verified_user)

        # 2. REST API protected endpoint must reject confirmation token with 401
        # Even if user is confirmed later, confirmation token still cannot authenticate
        self.user.confirmed = True
        db.session.commit()
        response_post = self.client.post(
            "/api/v1/posts",
            headers={
                "Authorization": f"Bearer {confirm_token}",
                "Content-Type": "application/json",
            },
            json={"body": "Malicious post with confirmation token"},
        )
        self.assertEqual(response_post.status_code, 401)

    def test_api_token_cannot_confirm_email(self):
        """Ensure an API authentication token cannot be used to confirm an email address."""
        # Confirm user temporarily to generate auth token
        self.user.confirmed = True
        db.session.commit()
        auth_token = self.user.generate_auth_token()

        # Reset confirmed status to test confirmation attempt
        self.user.confirmed = False
        db.session.commit()

        # Attempting to confirm with the auth token must fail
        result = self.user.confirm(auth_token)
        self.assertFalse(result)
        self.assertFalse(self.user.confirmed)

    def test_email_change_token_isolation(self):
        """Ensure email change tokens cannot be substituted for auth or confirmation."""
        change_token = self.user.generate_email_change_token("new@example.com")

        # Must not authenticate API
        self.assertIsNone(User.verify_auth_token(change_token))

        # Must not confirm account
        self.assertFalse(self.user.confirm(change_token))

        # Confirmation token must not succeed in email change
        confirm_token = self.user.generate_confirmation_token()
        self.assertFalse(self.user.change_email(confirm_token))

        # API token must not succeed in email change
        auth_token = self.user.generate_auth_token()
        self.assertFalse(self.user.change_email(auth_token))

    def test_expired_tokens_safely_rejected(self):
        """Ensure expired tokens are safely rejected without crashing."""
        confirm_token = self.user.generate_confirmation_token()
        auth_token = self.user.generate_auth_token()

        # Validate with max_age=-1 to simulate expiration
        self.assertFalse(self.user.confirm(confirm_token, expiration=-1))
        self.assertIsNone(User.verify_auth_token(auth_token, max_age=-1))
        self.assertFalse(
            self.user.change_email(
                self.user.generate_email_change_token("new@example.com"), expiration=-1
            )
        )

    def test_tampered_and_malformed_tokens_safely_rejected(self):
        """Ensure malformed, None, or tampered tokens do not leak secrets or crash."""
        malformed_tokens = [
            "",
            None,
            "invalid.token",
            "not-a-token",
            "12345",
            self.user.generate_confirmation_token() + "tampered",
        ]

        for token in malformed_tokens:
            self.assertFalse(self.user.confirm(token))
            self.assertIsNone(User.verify_auth_token(token))
            self.assertFalse(self.user.change_email(token))

    def test_valid_confirmation_flow(self):
        """Ensure legitimate confirmation token successfully confirms user."""
        self.assertFalse(self.user.confirmed)
        token = self.user.generate_confirmation_token()
        self.assertTrue(self.user.confirm(token))
        self.assertTrue(self.user.confirmed)
