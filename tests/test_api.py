import base64
import json
import unittest

from app import create_app, db
from app.models import Role, User


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

        # 2. Get auth token
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
