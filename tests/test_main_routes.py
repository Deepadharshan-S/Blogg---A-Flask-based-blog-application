import re
import unittest

from app import create_app, db
from app.models import Comment, Permission, Post, Role, User


class MainRoutesTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        Role.insert_roles()
        self.client = self.app.test_client()

        # Roles
        admin_role = Role.query.filter_by(name="Administrator").first()
        mod_role = Role.query.filter_by(name="Moderator").first()
        user_role = Role.query.filter_by(name="User").first()

        # Users
        self.admin = User(
            email="admin@example.com",
            username="adminuser",
            password="Password123!",
            confirmed=True,
            role=admin_role,
        )
        self.moderator = User(
            email="mod@example.com",
            username="moduser",
            password="Password123!",
            confirmed=True,
            role=mod_role,
        )
        self.author = User(
            email="author@example.com",
            username="authoruser",
            password="Password123!",
            confirmed=True,
            role=user_role,
        )
        self.reader = User(
            email="reader@example.com",
            username="readeruser",
            password="Password123!",
            confirmed=True,
            role=user_role,
        )
        db.session.add_all([self.admin, self.moderator, self.author, self.reader])
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def _get_csrf_token(self):
        res = self.client.get("/")
        match = re.search(r'<meta name="csrf-token" content="([^"]+)">', res.get_data(as_text=True))
        if not match:
            match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', res.get_data(as_text=True))
        self.assertTrue(match, "CSRF token not found")
        return match.group(1)

    def _login(self, email, password="Password123!"):
        token = self._get_csrf_token()
        return self.client.post(
            "/auth/login",
            headers={"X-CSRFToken": token},
            data={"email": email, "password": password},
            follow_redirects=True,
        )

    def test_anonymous_access_restrictions(self):
        """Ensure unauthenticated users are redirected to login for protected pages."""
        protected_routes = ["/edit-profile", "/moderate", "/all", "/followed"]
        for route in protected_routes:
            res = self.client.get(route)
            self.assertEqual(res.status_code, 302)
            self.assertIn("/auth/login", res.headers.get("Location", ""))

    def test_post_creation_and_markdown_sanitization(self):
        """Ensure post creation converts Markdown and sanitizes dangerous HTML."""
        self._login(self.author.email)
        token = self._get_csrf_token()

        post_body = "Hello **world**! <script>alert('xss')</script> This is a safe paragraph."
        res = self.client.post(
            "/",
            headers={"X-CSRFToken": token},
            data={"body": post_body},
            follow_redirects=True,
        )
        self.assertEqual(res.status_code, 200)

        post = Post.query.filter_by(author=self.author).first()
        self.assertIsNotNone(post)
        self.assertIn("<strong>world</strong>", post.body_html)
        self.assertNotIn("<script>", post.body_html)
        self.assertIn("1 min read", post.reading_time)

    def test_post_editing_permissions(self):
        """Ensure only author or administrator can edit a post."""
        # 1. Author creates a post
        post = Post(body="Original post content", author=self.author)
        db.session.add(post)
        db.session.commit()

        # 2. Non-author reader attempts to edit -> 403 Forbidden
        self._login(self.reader.email)
        token = self._get_csrf_token()
        res_reader_get = self.client.get(f"/edit/{post.id}")
        self.assertEqual(res_reader_get.status_code, 403)
        res_reader_post = self.client.post(
            f"/edit/{post.id}",
            headers={"X-CSRFToken": token},
            data={"body": "Hacked content by reader"},
        )
        self.assertEqual(res_reader_post.status_code, 403)

        # 3. Author successfully edits post
        self._login(self.author.email)
        token = self._get_csrf_token()
        res_author = self.client.post(
            f"/edit/{post.id}",
            headers={"X-CSRFToken": token},
            data={"body": "Author updated content"},
            follow_redirects=True,
        )
        self.assertEqual(res_author.status_code, 200)
        db.session.refresh(post)
        self.assertEqual(post.body, "Author updated content")

        # 4. Administrator can also edit post
        self._login(self.admin.email)
        token = self._get_csrf_token()
        res_admin = self.client.post(
            f"/edit/{post.id}",
            headers={"X-CSRFToken": token},
            data={"body": "Admin moderated content"},
            follow_redirects=True,
        )
        self.assertEqual(res_admin.status_code, 200)
        db.session.refresh(post)
        self.assertEqual(post.body, "Admin moderated content")

    def test_comments_creation_and_moderation(self):
        """Ensure comments can be posted and moderated by authorized moderators."""
        post = Post(body="Post with comments", author=self.author)
        db.session.add(post)
        db.session.commit()

        # Reader comments on author's post
        self._login(self.reader.email)
        token = self._get_csrf_token()
        res_comment = self.client.post(
            f"/post/{post.id}",
            headers={"X-CSRFToken": token},
            data={"body": "Great article!"},
            follow_redirects=True,
        )
        self.assertEqual(res_comment.status_code, 200)

        comment = Comment.query.filter_by(post=post).first()
        self.assertIsNotNone(comment)
        self.assertEqual(comment.author, self.reader)
        self.assertFalse(comment.disabled)

        # Regular user cannot access moderation dashboard
        res_mod_unauth = self.client.get("/moderate")
        self.assertEqual(res_mod_unauth.status_code, 403)

        # Moderator can access moderation dashboard
        self._login(self.moderator.email)
        res_mod_auth = self.client.get("/moderate")
        self.assertEqual(res_mod_auth.status_code, 200)
        self.assertIn("Comment Moderation", res_mod_auth.get_data(as_text=True))

        # Moderator disables comment
        token_mod = self._get_csrf_token()
        res_disable = self.client.post(
            f"/moderate/disable/{comment.id}",
            headers={"X-CSRFToken": token_mod},
            follow_redirects=True,
        )
        self.assertEqual(res_disable.status_code, 200)
        db.session.refresh(comment)
        self.assertTrue(comment.disabled)

        # Public post view now masks the disabled comment
        res_view = self.client.get(f"/post/{post.id}")
        self.assertIn(
            "This comment has been disabled by a moderator.", res_view.get_data(as_text=True)
        )

    def test_user_profile_and_edit_profile(self):
        """Ensure user profile viewing and profile editing (self and admin)."""
        # View user profile
        res_profile = self.client.get(f"/user/{self.author.username}")
        self.assertEqual(res_profile.status_code, 200)
        self.assertIn(self.author.username, res_profile.get_data(as_text=True))

        # Author updates their own profile
        self._login(self.author.email)
        token = self._get_csrf_token()
        res_edit = self.client.post(
            "/edit-profile",
            headers={"X-CSRFToken": token},
            data={"name": "Real Author", "location": "New York", "about_me": "Writing tech blogs"},
            follow_redirects=True,
        )
        self.assertEqual(res_edit.status_code, 200)
        db.session.refresh(self.author)
        self.assertEqual(self.author.name, "Real Author")
        self.assertEqual(self.author.location, "New York")

        # Admin edits author's profile via /edit-profile/<id>
        self._login(self.admin.email)
        token = self._get_csrf_token()
        res_admin_edit = self.client.post(
            f"/edit-profile/{self.author.id}",
            headers={"X-CSRFToken": token},
            data={
                "email": "author_new@example.com",
                "username": "authoruser",
                "confirmed": True,
                "role": self.author.role_id,
                "name": "Admin Edited Author",
                "location": "Boston",
                "about_me": "Updated by admin",
            },
            follow_redirects=True,
        )
        self.assertEqual(res_admin_edit.status_code, 200)
        db.session.refresh(self.author)
        self.assertEqual(self.author.email, "author_new@example.com")
        self.assertEqual(self.author.name, "Admin Edited Author")

    def test_feed_filters_and_search(self):
        """Ensure feed filter cookies and search queries function correctly."""
        self._login(self.author.email)

        # All posts filter
        res_all = self.client.get("/all")
        self.assertEqual(res_all.status_code, 302)
        cookie_header = res_all.headers.get("Set-Cookie", "")
        self.assertIn("show_followed=", cookie_header)

        # Followed posts filter
        res_followed = self.client.get("/followed")
        self.assertEqual(res_followed.status_code, 302)
        cookie_header2 = res_followed.headers.get("Set-Cookie", "")
        self.assertIn("show_followed=1", cookie_header2)

        # Search posts and users
        post = Post(body="UniqueSearchKeyword in post body", author=self.author)
        db.session.add(post)
        db.session.commit()

        res_search = self.client.get("/search?q=UniqueSearchKeyword")
        self.assertEqual(res_search.status_code, 200)
        self.assertIn("UniqueSearchKeyword", res_search.get_data(as_text=True))

        res_search_user = self.client.get(f"/search?q={self.author.username}")
        self.assertEqual(res_search_user.status_code, 200)
        self.assertIn(self.author.username, res_search_user.get_data(as_text=True))

    def test_comment_authorization_and_anonymous_submission(self):
        """Ensure anonymous comment submissions do not crash and COMMENT permission is enforced."""
        post = Post(body="Post for comment permission tests", author=self.author)
        db.session.add(post)
        db.session.commit()

        # 1. Anonymous GET works cleanly
        res_get = self.client.get(f"/post/{post.id}")
        self.assertEqual(res_get.status_code, 200)

        # 2. Anonymous POST is redirected to login without 500 error or database insertion
        csrf_token = self._get_csrf_token()
        res_anon_post = self.client.post(
            f"/post/{post.id}",
            headers={"X-CSRFToken": csrf_token},
            data={"body": "Anonymous comment"},
            follow_redirects=False,
        )
        self.assertEqual(res_anon_post.status_code, 302)
        self.assertIn("/auth/login", res_anon_post.headers.get("Location", ""))
        self.assertEqual(Comment.query.filter_by(post=post).count(), 0)

        # 3. Authenticated user without COMMENT permission receives 403 Forbidden
        muted_role = Role(name="MutedUser", permissions=Permission.FOLLOW)
        db.session.add(muted_role)
        muted_user = User(
            email="muted@example.com",
            username="muteduser",
            password="Password123!",
            confirmed=True,
            role=muted_role,
        )
        db.session.add(muted_user)
        db.session.commit()

        self._login(muted_user.email)
        csrf_token = self._get_csrf_token()
        res_muted_post = self.client.post(
            f"/post/{post.id}",
            headers={"X-CSRFToken": csrf_token},
            data={"body": "Comment from muted user"},
            follow_redirects=False,
        )
        self.assertEqual(res_muted_post.status_code, 403)
        self.assertEqual(Comment.query.filter_by(post=post).count(), 0)

        # 4. Invalid form submission by authenticated user does not create a comment
        self._login(self.reader.email)
        csrf_token = self._get_csrf_token()
        res_invalid = self.client.post(
            f"/post/{post.id}",
            headers={"X-CSRFToken": csrf_token},
            data={"body": ""},
            follow_redirects=False,
        )
        self.assertEqual(res_invalid.status_code, 200)
        self.assertEqual(Comment.query.filter_by(post=post).count(), 0)

        # 5. Authenticated user with COMMENT permission succeeds
        csrf_token = self._get_csrf_token()
        res_valid = self.client.post(
            f"/post/{post.id}",
            headers={"X-CSRFToken": csrf_token},
            data={"body": "Valid authorized comment"},
            follow_redirects=True,
        )
        self.assertEqual(res_valid.status_code, 200)
        self.assertEqual(Comment.query.filter_by(post=post).count(), 1)
        self.assertEqual(Comment.query.filter_by(post=post).first().author, self.reader)

    def test_like_route_referer_validation(self):
        """BLOGG-SEC-008: Ensure like route validates Referer and does not allow open redirects."""
        post = Post(body="Post for like referer testing", author=self.author)
        db.session.add(post)
        db.session.commit()

        self._login(self.reader.email)
        csrf_token = self._get_csrf_token()

        # 1. External Referer rejected, falls back to index
        res_ext = self.client.post(
            f"/like/{post.id}",
            headers={"X-CSRFToken": csrf_token, "Referer": "https://attacker.example/malicious"},
            follow_redirects=False,
        )
        self.assertEqual(res_ext.status_code, 302)
        self.assertEqual(res_ext.headers.get("Location"), "/")

        # 2. Protocol-relative Referer rejected
        csrf_token = self._get_csrf_token()
        res_proto = self.client.post(
            f"/like/{post.id}",
            headers={"X-CSRFToken": csrf_token, "Referer": "//attacker.example/path"},
            follow_redirects=False,
        )
        self.assertEqual(res_proto.status_code, 302)
        self.assertEqual(res_proto.headers.get("Location"), "/")

        # 3. Absent Referer falls back to index
        csrf_token = self._get_csrf_token()
        res_none = self.client.post(
            f"/like/{post.id}",
            headers={"X-CSRFToken": csrf_token},
            follow_redirects=False,
        )
        self.assertEqual(res_none.status_code, 302)
        self.assertEqual(res_none.headers.get("Location"), "/")

        # 4. Valid same-origin Referer preserved
        csrf_token = self._get_csrf_token()
        res_local = self.client.post(
            f"/like/{post.id}",
            headers={"X-CSRFToken": csrf_token, "Referer": f"http://localhost/post/{post.id}"},
            follow_redirects=False,
        )
        self.assertEqual(res_local.status_code, 302)
        self.assertEqual(res_local.headers.get("Location"), f"http://localhost/post/{post.id}")
