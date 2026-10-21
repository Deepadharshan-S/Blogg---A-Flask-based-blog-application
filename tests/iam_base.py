"""Shared helpers for the IAM test suites (not collected by pytest)."""

import html
import re
import unittest

from flask import g

from app import create_app, db
from app.models import Role, User


class IAMTestCase(unittest.TestCase):
    """App factory, CSRF and authentication helpers for IAM tests."""

    def setUp(self):
        self.app = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()

        # The app context pushed above is reused by every request Flask
        # serves, so `g` (flask-wtf caches the CSRF token there,
        # flask-login the current user) would leak between the multiple
        # test clients these tests use. Clear it after each request to
        # restore production-like per-request isolation.
        @self.app.teardown_request
        def _isolate_g(err=None):  # noqa: ARG001
            g.pop("csrf_token", None)
            g.pop("_login_user", None)

        db.create_all()
        Role.insert_roles()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------
    def get_csrf(self, path="/auth/login", client=None):
        client = client or self.client
        response = client.get(path)
        text = response.get_data(as_text=True)
        match = re.search(r'<meta name="csrf-token" content="([^"]+)">', text)
        if not match:
            match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', text)
        self.assertIsNotNone(match, f"Could not extract CSRF token from {path}")
        return match.group(1)

    def post_form(self, path, data=None, page=None, client=None, follow_redirects=False):
        """POST a form with a freshly extracted CSRF token (header + field)."""
        client = client or self.client
        token = self.get_csrf(page or path, client=client)
        payload = dict(data or {})
        payload.setdefault("csrf_token", token)
        return client.post(
            path,
            headers={"X-CSRFToken": token},
            data=payload,
            follow_redirects=follow_redirects,
        )

    def page_text(self, response):
        """Response body with HTML entities unescaped (flashes use &#39; etc.)."""
        return html.unescape(response.get_data(as_text=True))

    def api_headers(self, token=None):
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def issue_token(self, client=None, scopes=None, **credentials):
        """POST /api/v1/tokens and return the JSON response body."""
        client = client or self.client
        body = {"email": "user@example.com", "password": "Password123!"}
        if scopes is not None:
            body["scopes"] = scopes
        body.update(credentials)
        response = client.post("/api/v1/tokens", headers=self.api_headers(), json=body)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.get_json()

    # ------------------------------------------------------------------
    # Fixture helpers
    # ------------------------------------------------------------------
    def make_user(
        self,
        email="user@example.com",
        password="Password123!",
        username=None,
        confirmed=True,
        role=None,
        **kwargs,
    ):
        user = User(
            email=email,
            username=username or email.split("@")[0],
            password=password,
            confirmed=confirmed,
            role=role,
            **kwargs,
        )
        db.session.add(user)
        db.session.commit()
        return user

    def admin_role(self):
        return Role.query.filter_by(name="Administrator").first()

    def login(self, email="user@example.com", password="Password123!", client=None):
        return self.post_form(
            "/auth/login",
            {"email": email, "password": password},
            page="/auth/login",
            client=client,
            follow_redirects=True,
        )

    def logout(self, client=None):
        """Sign out via the CSRF-protected POST endpoint (logout is POST-only)."""
        client = client or self.client
        return self.post_form("/auth/logout", {}, page="/", client=client, follow_redirects=True)
