"""Opaque API token lifecycle: issue, scope enforcement, revoke, expiry."""

from datetime import timedelta

from app import db
from app.models import ApiToken, AuditEvent, utc_now
from app.security import Event
from tests.iam_base import IAMTestCase


class APITokenTestCase(IAMTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.make_user()

    def test_issue_token_returns_opaque_secret_stored_hashed(self):
        body = self.issue_token(name="cli", scopes=["posts:read", "posts:write"], expiration=600)
        token = body["token"]
        self.assertEqual(body["scopes"], ["posts:read", "posts:write"])
        self.assertEqual(body["expiration"], 600)

        row = db.session.get(ApiToken, body["token_id"])
        self.assertIsNotNone(row)
        # Only the SHA-256 hash is persisted - never the raw secret.
        self.assertEqual(row.token_hash, ApiToken.hash_token(token))
        self.assertNotIn(token, row.token_hash)
        self.assertIsNotNone(row.expires_at)

        # Token issuance is audited.
        event = AuditEvent.query.filter_by(event=Event.TOKEN_ISSUED, actor_id=self.user.id).first()
        self.assertIsNotNone(event)
        self.assertEqual(event.target_label, "cli")

        # The token authenticates API calls and records last use.
        response = self.client.get("/api/v1/posts", headers=self.api_headers(token))
        self.assertEqual(response.status_code, 200)
        db.session.refresh(row)
        self.assertIsNotNone(row.last_used_at)

    def test_scope_enforced_on_write_endpoint(self):
        read_only = self.issue_token(scopes=["posts:read"])["token"]
        response = self.client.post(
            "/api/v1/posts",
            headers=self.api_headers(read_only),
            json={"body": "should not be allowed"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("posts:write", response.get_json()["message"])

        writer = self.issue_token(scopes=["posts:write"])["token"]
        response = self.client.post(
            "/api/v1/posts",
            headers=self.api_headers(writer),
            json={"body": "allowed by scope"},
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(self.user.posts.count(), 1)

    def test_unknown_scope_rejected(self):
        response = self.client.post(
            "/api/v1/tokens",
            headers=self.api_headers(),
            json={
                "email": self.user.email,
                "password": "Password123!",
                "scopes": ["superuser", "posts:read"],
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Unknown scope", response.get_json()["message"])

    def test_token_list_and_revoke(self):
        body = self.issue_token(scopes=["tokens:manage", "posts:read"])
        token = body["token"]
        token_id = body["token_id"]

        response = self.client.get("/api/v1/tokens", headers=self.api_headers(token))
        self.assertEqual(response.status_code, 200)
        tokens = response.get_json()["tokens"]
        self.assertEqual(len(tokens), 1)
        self.assertNotIn("token", tokens[0])  # no secret in listings

        response = self.client.delete(f"/api/v1/tokens/{token_id}", headers=self.api_headers(token))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["revoked"])
        self.assertIsNotNone(
            AuditEvent.query.filter_by(event=Event.TOKEN_REVOKED, actor_id=self.user.id).first()
        )

        # The revoked token stops working immediately.
        response = self.client.get("/api/v1/posts", headers=self.api_headers(token))
        self.assertEqual(response.status_code, 401)
        self.assertIn("revoked", response.get_json()["message"])

    def test_expired_token_rejected(self):
        token = self.issue_token(scopes=["posts:read"])["token"]
        row = ApiToken.query.filter_by(token_hash=ApiToken.hash_token(token)).one()
        row.expires_at = utc_now() - timedelta(seconds=1)
        db.session.add(row)
        db.session.commit()

        response = self.client.get("/api/v1/posts", headers=self.api_headers(token))
        self.assertEqual(response.status_code, 401)
        self.assertIn("expired", response.get_json()["message"])

    def test_invalid_token_rejected(self):
        response = self.client.get("/api/v1/posts", headers=self.api_headers("not-a-real-token"))
        self.assertEqual(response.status_code, 401)
        self.assertIn("Invalid", response.get_json()["message"])

    def test_legacy_signed_token_still_accepted(self):
        legacy = self.user.generate_auth_token()
        response = self.client.get("/api/v1/posts", headers=self.api_headers(legacy))
        self.assertEqual(response.status_code, 200)

        # Legacy tokens are full access (no scope restrictions).
        response = self.client.post(
            "/api/v1/posts",
            headers=self.api_headers(legacy),
            json={"body": "legacy write"},
        )
        self.assertEqual(response.status_code, 201)

    def test_token_endpoints_require_authentication(self):
        response = self.client.get("/api/v1/tokens")
        self.assertEqual(response.status_code, 401)
        response = self.client.delete("/api/v1/tokens/1")
        self.assertEqual(response.status_code, 401)
        response = self.client.get("/api/v1/me/sessions")
        self.assertEqual(response.status_code, 401)

        # A default-scoped token lacks tokens:manage.
        default_token = self.issue_token()["token"]
        response = self.client.get("/api/v1/tokens", headers=self.api_headers(default_token))
        self.assertEqual(response.status_code, 403)
        self.assertIn("tokens:manage", response.get_json()["message"])

    def test_session_endpoints_list_and_revoke(self):
        self.login()
        token = self.issue_token(scopes=["tokens:manage"])["token"]

        response = self.client.get("/api/v1/me/sessions", headers=self.api_headers(token))
        self.assertEqual(response.status_code, 200)
        sessions = response.get_json()["sessions"]
        self.assertEqual(len(sessions), 1)
        jti = sessions[0]["jti"]
        self.assertEqual(response.get_json()["current_jti"], jti)

        # Revoke the browser session through the API.
        response = self.client.delete(f"/api/v1/me/sessions/{jti}", headers=self.api_headers(token))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["revoked"])

        # The browser session is dead now.
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/login", response.headers["Location"])

    def test_cannot_revoke_foreign_session_or_token(self):
        other = self.make_user(email="other@example.com", username="other")
        other_token = self.issue_token(
            scopes=["tokens:manage"], email=other.email, password="Password123!"
        )["token"]

        # Our own token id must not be visible/deletable by the other account.
        my_body = self.issue_token(scopes=["tokens:manage"])
        response = self.client.delete(
            f"/api/v1/tokens/{my_body['token_id']}", headers=self.api_headers(other_token)
        )
        self.assertEqual(response.status_code, 403)

        # Foreign sessions are 404 for us.
        client_other = self.app.test_client()
        self.login(email=other.email, client=client_other)
        with client_other.session_transaction() as other_session:
            other_jti = other_session.get("session_jti")
        response = self.client.delete(
            f"/api/v1/me/sessions/{other_jti}", headers=self.api_headers(my_body["token"])
        )
        self.assertEqual(response.status_code, 404)
