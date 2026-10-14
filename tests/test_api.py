import base64
import json
import unittest

from app import create_app, db
from app.models import Post, Role, User


class APITestCase(unittest.TestCase):
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

    def get_api_headers(self, token=None, username=None, password=None):
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif username and password:
            creds = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("utf-8")
            headers["Authorization"] = f"Basic {creds}"
        return headers

    def test_404_json(self):
        response = self.client.get("/api/v1/nonexistent", headers=self.get_api_headers())
        self.assertEqual(response.status_code, 404)
        json_response = json.loads(response.get_data(as_text=True))
        self.assertEqual(json_response["error"], "not found")

    def test_unauthenticated_post_creation(self):
        response = self.client.post(
            "/api/v1/posts",
            headers=self.get_api_headers(),
            data=json.dumps({"body": "Unauthorized post"}),
        )
        self.assertEqual(response.status_code, 401)

    def test_token_auth_and_post_lifecycle(self):
        # 1. Create a confirmed user with Write permission
        user = User(
            email="author@example.com", username="author", password="Password123!", confirmed=True
        )
        db.session.add(user)
        db.session.commit()

        # 2. Get auth token via Basic Auth
        response = self.client.post(
            "/api/v1/tokens",
            headers=self.get_api_headers(username="author@example.com", password="Password123!"),
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.get_data(as_text=True))
        token = data.get("token")
        self.assertIsNotNone(token)

        # 3. Create a post using Bearer token
        post_content = "This is a test post written through the new REST API."
        response = self.client.post(
            "/api/v1/posts",
            headers=self.get_api_headers(token=token),
            data=json.dumps({"body": post_content}),
        )
        self.assertEqual(response.status_code, 201)
        post_data = json.loads(response.get_data(as_text=True))
        post_id = post_data["id"]
        self.assertEqual(post_data["body"], post_content)
        self.assertEqual(post_data["author_username"], "author")
        self.assertEqual(post_data["reading_time"], "1 min read")

        # 4. Fetch post by ID
        response = self.client.get(f"/api/v1/posts/{post_id}", headers=self.get_api_headers())
        self.assertEqual(response.status_code, 200)

        # 5. Like post via API
        response = self.client.post(
            f"/api/v1/posts/{post_id}/like", headers=self.get_api_headers(token=token)
        )
        self.assertEqual(response.status_code, 200)
        like_data = json.loads(response.get_data(as_text=True))
        self.assertTrue(like_data["liked"])
        self.assertEqual(like_data["likes_count"], 1)

        # 6. Fetch user profile via API
        response = self.client.get("/api/v1/users/author", headers=self.get_api_headers())
        self.assertEqual(response.status_code, 200)
        user_data = json.loads(response.get_data(as_text=True))
        self.assertEqual(user_data["username"], "author")
        self.assertEqual(user_data["posts_count"], 1)

    def test_token_auth_failures_and_scoping(self):
        """Ensure token generation enforces credentials and confirmation, and rejects scoped tokens."""
        # Unconfirmed user
        unconfirmed = User(
            email="unconf_api@example.com",
            username="unconfapi",
            password="Password123!",
            confirmed=False,
        )
        # Confirmed user
        confirmed = User(
            email="conf_api@example.com",
            username="confapi",
            password="Password123!",
            confirmed=True,
        )
        db.session.add_all([unconfirmed, confirmed])
        db.session.commit()

        # Unconfirmed account requesting token -> 403 Forbidden
        res_unconf = self.client.post(
            "/api/v1/tokens",
            headers=self.get_api_headers(),
            data=json.dumps({"email": "unconf_api@example.com", "password": "Password123!"}),
        )
        self.assertEqual(res_unconf.status_code, 403)

        # Invalid credentials -> 401 Unauthorized
        res_bad_pw = self.client.post(
            "/api/v1/tokens",
            headers=self.get_api_headers(),
            data=json.dumps({"email": "conf_api@example.com", "password": "WrongPassword!"}),
        )
        self.assertEqual(res_bad_pw.status_code, 401)

        # Confirmation token used as Bearer auth token -> 401 Unauthorized
        confirm_token = confirmed.generate_confirmation_token()
        # User attempts to create post with confirmation token -> rejected
        res_scope_post = self.client.post(
            "/api/v1/posts",
            headers=self.get_api_headers(token=confirm_token),
            data=json.dumps({"body": "Should fail with confirmation token"}),
        )
        self.assertEqual(res_scope_post.status_code, 401)

    def test_post_creation_validation_and_editing(self):
        """Ensure API post validation, editing permissions, and 404s work correctly."""
        user1 = User(
            email="writer1@example.com", username="writer1", password="Password123!", confirmed=True
        )
        user2 = User(
            email="writer2@example.com", username="writer2", password="Password123!", confirmed=True
        )
        db.session.add_all([user1, user2])
        db.session.commit()

        token1 = user1.generate_auth_token()
        token2 = user2.generate_auth_token()

        # Empty body -> 400 Bad Request
        res_empty = self.client.post(
            "/api/v1/posts",
            headers=self.get_api_headers(token=token1),
            data=json.dumps({"body": "   "}),
        )
        self.assertEqual(res_empty.status_code, 400)

        # Valid post creation
        res_post = self.client.post(
            "/api/v1/posts",
            headers=self.get_api_headers(token=token1),
            data=json.dumps({"body": "Writer 1 post"}),
        )
        self.assertEqual(res_post.status_code, 201)
        post_id = res_post.get_json()["id"]

        # User 2 tries to edit User 1's post -> 403 Forbidden
        res_unauth_edit = self.client.put(
            f"/api/v1/posts/{post_id}",
            headers=self.get_api_headers(token=token2),
            data=json.dumps({"body": "Hijacked post"}),
        )
        self.assertEqual(res_unauth_edit.status_code, 403)

        # User 1 successfully edits own post -> 200 OK
        res_edit = self.client.put(
            f"/api/v1/posts/{post_id}",
            headers=self.get_api_headers(token=token1),
            data=json.dumps({"body": "Updated body by writer 1"}),
        )
        self.assertEqual(res_edit.status_code, 200)
        self.assertEqual(res_edit.get_json()["body"], "Updated body by writer 1")

        # Edit non-existent post -> 404 Not Found
        res_not_found = self.client.put(
            "/api/v1/posts/99999",
            headers=self.get_api_headers(token=token1),
            data=json.dumps({"body": "Does not exist"}),
        )
        self.assertEqual(res_not_found.status_code, 404)

        # Edit with empty body -> 400 Bad Request
        res_empty_edit = self.client.put(
            f"/api/v1/posts/{post_id}",
            headers=self.get_api_headers(token=token1),
            data=json.dumps({"body": ""}),
        )
        self.assertEqual(res_empty_edit.status_code, 400)

    def test_posts_listing_pagination_and_user_endpoints(self):
        """Ensure GET /api/v1/posts and GET /api/v1/users/<username>/posts paginate correctly."""
        user = User(
            email="blogger@example.com", username="blogger", password="Password123!", confirmed=True
        )
        db.session.add(user)
        db.session.commit()

        # Seed 5 posts
        for i in range(5):
            p = Post(body=f"Post number {i}", author=user)
            db.session.add(p)
        db.session.commit()

        # 1. Fetch posts with per_page=2
        res_posts = self.client.get(
            "/api/v1/posts?page=1&per_page=2", headers=self.get_api_headers()
        )
        self.assertEqual(res_posts.status_code, 200)
        data = res_posts.get_json()
        self.assertEqual(len(data["posts"]), 2)
        self.assertEqual(data["total"], 5)
        self.assertEqual(data["pages"], 3)
        self.assertIsNotNone(data["next_url"])

        # 2. Fetch user posts
        res_user_posts = self.client.get(
            "/api/v1/users/blogger/posts?page=1&per_page=3", headers=self.get_api_headers()
        )
        self.assertEqual(res_user_posts.status_code, 200)
        u_data = res_user_posts.get_json()
        self.assertEqual(len(u_data["posts"]), 3)
        self.assertEqual(u_data["user"], "blogger")

        # 3. Non-existent user -> 404
        res_nonexistent = self.client.get(
            "/api/v1/users/nonexistent_user", headers=self.get_api_headers()
        )
        self.assertEqual(res_nonexistent.status_code, 404)
        res_nonexistent_posts = self.client.get(
            "/api/v1/users/nonexistent_user/posts", headers=self.get_api_headers()
        )
        self.assertEqual(res_nonexistent_posts.status_code, 404)
