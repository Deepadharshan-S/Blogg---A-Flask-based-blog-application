import re
import unittest

from app import create_app, db
from app.models import Comment, Post, Role, User


class CSRFAndRoutesTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        Role.insert_roles()
        self.client = self.app.test_client()

        # Create moderator/admin and regular users
        self.user1 = User(
            email="user1@example.com",
            username="user1",
            password="Password123!",
            confirmed=True,
        )
        self.user2 = User(
            email="user2@example.com",
            username="user2",
            password="Password123!",
            confirmed=True,
        )
        mod_role = Role.query.filter_by(name="Moderator").first()
        self.mod = User(
            email="mod@example.com",
            username="moderator",
            password="Password123!",
            confirmed=True,
            role=mod_role,
        )
        db.session.add_all([self.user1, self.user2, self.mod])
        db.session.commit()

        # Create a post and comment
        self.post = Post(body="Test post for CSRF", author=self.user1)
        db.session.add(self.post)
        db.session.commit()

        self.comment = Comment(body="Test comment", author=self.user2, post=self.post)
        db.session.add(self.comment)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def _get_csrf_token(self):
        """Helper to get a valid CSRF token associated with the client session."""
        response = self.client.get("/")
        match = re.search(
            r'<meta name="csrf-token" content="([^"]+)">', response.get_data(as_text=True)
        )
        self.assertTrue(match, "CSRF token meta tag not found in HTML")
        return match.group(1)

    def _login(self, email="user1@example.com", password="Password123!"):
        token = self._get_csrf_token()
        return self.client.post(
            "/auth/login",
            headers={"X-CSRFToken": token},
            data={"email": email, "password": password},
            follow_redirects=True,
        )

    def test_state_changing_get_routes_rejected(self):
        """Ensure state-changing routes reject GET requests with 405 Method Not Allowed."""
        self._login()

        # Follow / Unfollow
        res_follow = self.client.get(f"/follow/{self.user2.username}")
        self.assertEqual(res_follow.status_code, 405)

        res_unfollow = self.client.get(f"/unfollow/{self.user2.username}")
        self.assertEqual(res_unfollow.status_code, 405)

        # Moderation enable / disable
        res_enable = self.client.get(f"/moderate/enable/{self.comment.id}")
        self.assertEqual(res_enable.status_code, 405)

        res_disable = self.client.get(f"/moderate/disable/{self.comment.id}")
        self.assertEqual(res_disable.status_code, 405)

    def test_browser_post_without_csrf_rejected(self):
        """Ensure POST requests without CSRF token are rejected with 400 Bad Request."""
        self._login()

        # Like endpoint without CSRF
        res_like = self.client.post(f"/like/{self.post.id}")
        self.assertEqual(res_like.status_code, 400)

        # Follow endpoint without CSRF
        res_follow = self.client.post(f"/follow/{self.user2.username}")
        self.assertEqual(res_follow.status_code, 400)

        # Unfollow endpoint without CSRF
        res_unfollow = self.client.post(f"/unfollow/{self.user2.username}")
        self.assertEqual(res_unfollow.status_code, 400)

        # Moderation enable without CSRF
        res_enable = self.client.post(f"/moderate/enable/{self.comment.id}")
        self.assertEqual(res_enable.status_code, 400)

        # Moderation disable without CSRF
        res_disable = self.client.post(f"/moderate/disable/{self.comment.id}")
        self.assertEqual(res_disable.status_code, 400)

    def test_like_post_with_csrf_succeeds(self):
        """Ensure liking a post with CSRF token succeeds via AJAX and standard POST."""
        self._login("user1@example.com")
        token = self._get_csrf_token()

        # AJAX Like request with X-CSRFToken
        res_ajax = self.client.post(
            f"/like/{self.post.id}",
            headers={"X-CSRFToken": token, "X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(res_ajax.status_code, 200)
        data = res_ajax.get_json()
        self.assertTrue(data["liked"])
        self.assertEqual(data["likes_count"], 1)
        self.assertTrue(self.user1.has_liked_post(self.post))

        # Unlike with another AJAX request
        res_ajax2 = self.client.post(
            f"/like/{self.post.id}",
            headers={"X-CSRFToken": token, "X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(res_ajax2.status_code, 200)
        data2 = res_ajax2.get_json()
        self.assertFalse(data2["liked"])
        self.assertEqual(data2["likes_count"], 0)
        self.assertFalse(self.user1.has_liked_post(self.post))

    def test_follow_and_unfollow_post_with_csrf(self):
        """Ensure follow and unfollow work correctly via POST with CSRF."""
        self._login("user1@example.com")
        token = self._get_csrf_token()

        self.assertFalse(self.user1.is_following(self.user2))

        # Follow user2 via POST with CSRF token in header
        res_follow = self.client.post(
            f"/follow/{self.user2.username}",
            headers={"X-CSRFToken": token},
            follow_redirects=True,
        )
        self.assertEqual(res_follow.status_code, 200)
        self.assertTrue(self.user1.is_following(self.user2))

        # Unfollow user2 via POST with CSRF token in form data
        res_unfollow = self.client.post(
            f"/unfollow/{self.user2.username}",
            data={"csrf_token": token},
            follow_redirects=True,
        )
        self.assertEqual(res_unfollow.status_code, 200)
        self.assertFalse(self.user1.is_following(self.user2))

    def test_moderate_enable_disable_post_with_csrf(self):
        """Ensure comment moderation requires MODERATE permission and valid CSRF."""
        # 1. Regular user cannot moderate (403)
        self._login("user1@example.com")
        token = self._get_csrf_token()
        res_unauth = self.client.post(
            f"/moderate/disable/{self.comment.id}",
            headers={"X-CSRFToken": token},
        )
        self.assertEqual(res_unauth.status_code, 403)

        # 2. Moderator can moderate
        self._login("mod@example.com")
        token_mod = self._get_csrf_token()

        # Disable comment
        res_dis = self.client.post(
            f"/moderate/disable/{self.comment.id}",
            headers={"X-CSRFToken": token_mod},
            follow_redirects=True,
        )
        self.assertEqual(res_dis.status_code, 200)
        db.session.refresh(self.comment)
        self.assertTrue(self.comment.disabled)

        # Enable comment
        res_en = self.client.post(
            f"/moderate/enable/{self.comment.id}",
            headers={"X-CSRFToken": token_mod},
            follow_redirects=True,
        )
        self.assertEqual(res_en.status_code, 200)
        db.session.refresh(self.comment)
        self.assertFalse(self.comment.disabled)

    def test_api_blueprint_is_csrf_exempt(self):
        """Ensure stateless REST API requests do not require CSRF tokens."""
        # Authenticate via API token
        auth_token = self.user1.generate_auth_token()

        # POST /api/v1/posts without CSRF token must succeed
        response = self.client.post(
            "/api/v1/posts",
            headers={
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json",
            },
            json={"body": "A stateless post via API without CSRF"},
        )
        self.assertEqual(response.status_code, 201)
