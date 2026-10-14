import base64
import json
import unittest

from itsdangerous import TimestampSigner

from app import create_app, db
from app.models import (
    RESET_PASSWORD_TOKEN_SALT,
    AnonymousUser,
    Comment,
    Permission,
    Post,
    Role,
    User,
)


class UserModelTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        Role.insert_roles()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_password_setter(self):
        u = User(password="cat")
        self.assertTrue(u.password_hash is not None)

    def test_no_password_getter(self):
        u = User(password="cat")
        with self.assertRaises(AttributeError):
            u.password

    def test_password_verification(self):
        u = User(password="cat")
        self.assertTrue(u.verify_password("cat"))
        self.assertFalse(u.verify_password("dog"))

    def test_password_salts_are_random(self):
        u = User(password="cat")
        u2 = User(password="cat")
        self.assertTrue(u.password_hash != u2.password_hash)

    def test_valid_reset_token_resets_password(self):
        u = User(email="reset@example.com", username="resetuser", password="OldPassword123!")
        db.session.add(u)
        db.session.commit()

        token = u.generate_reset_token()
        self.assertIsNotNone(token)
        self.assertTrue(User.reset_password(token, "NewPassword123!"))

        db.session.refresh(u)
        self.assertTrue(u.verify_password("NewPassword123!"))
        self.assertFalse(u.verify_password("OldPassword123!"))

    def test_reset_token_single_use(self):
        u = User(email="singleuse@example.com", username="singleuse", password="OldPassword123!")
        db.session.add(u)
        db.session.commit()

        token = u.generate_reset_token()
        self.assertTrue(User.reset_password(token, "NewPassword123!"))

        # Reusing the same token must fail
        self.assertFalse(User.reset_password(token, "AnotherPassword123!"))
        db.session.refresh(u)
        self.assertTrue(u.verify_password("NewPassword123!"))

    def test_reset_token_invalidated_by_password_change(self):
        u = User(email="inv@example.com", username="invuser", password="OldPassword123!")
        db.session.add(u)
        db.session.commit()

        token = u.generate_reset_token()
        u.password = "ChangedDirectly123!"
        db.session.add(u)
        db.session.commit()

        self.assertFalse(User.reset_password(token, "NewPassword123!"))

    def test_reset_token_nonexistent_user(self):
        signer = TimestampSigner(self.app.config["SECRET_KEY"], salt=RESET_PASSWORD_TOKEN_SALT)
        data = {"reset": 999999, "hash": "nonexistenthash1"}
        json_data = json.dumps(data).encode("utf-8")
        base64_data = base64.urlsafe_b64encode(json_data).decode("utf-8")
        signed_token = signer.sign(base64_data.encode("utf-8")).decode("utf-8")

        self.assertFalse(User.reset_password(signed_token, "NewPassword123!"))

    def test_reset_token_invalid_and_malformed(self):
        self.assertFalse(User.reset_password(None, "NewPassword123!"))
        self.assertFalse(User.reset_password("", "NewPassword123!"))
        self.assertFalse(User.reset_password("invalid.token", "NewPassword123!"))
        self.assertFalse(User.reset_password(12345, "NewPassword123!"))

    def test_user_role(self):
        u = User(email="john@example.com", password="cat")
        self.assertTrue(u.can(Permission.FOLLOW))
        self.assertTrue(u.can(Permission.COMMENT))
        self.assertTrue(u.can(Permission.WRITE))
        self.assertFalse(u.can(Permission.MODERATE))
        self.assertFalse(u.can(Permission.ADMIN))

    def test_anonymous_user(self):
        u = AnonymousUser()
        self.assertFalse(u.can(Permission.FOLLOW))
        self.assertFalse(u.can(Permission.COMMENT))
        self.assertFalse(u.can(Permission.WRITE))
        self.assertFalse(u.can(Permission.MODERATE))
        self.assertFalse(u.can(Permission.ADMIN))

    def test_user_cascade_deletion(self):
        """Ensure deleting a user cascades to their posts and comments."""
        u1 = User(email="author@example.com", username="author", password="Password123!")
        u2 = User(email="commenter@example.com", username="commenter", password="Password123!")
        db.session.add_all([u1, u2])
        db.session.commit()

        p = Post(body="Post by author", author=u1)
        db.session.add(p)
        db.session.commit()

        c1 = Comment(body="Comment by author", post=p, author=u1)
        c2 = Comment(body="Comment by commenter", post=p, author=u2)
        db.session.add_all([c1, c2])
        db.session.commit()

        db.session.delete(u1)
        db.session.commit()

        self.assertIsNone(db.session.get(User, u1.id))
        self.assertIsNone(db.session.get(Post, p.id))
        self.assertIsNone(db.session.get(Comment, c1.id))
        self.assertIsNone(db.session.get(Comment, c2.id))

    def test_post_cascade_deletion(self):
        """Ensure deleting a post cascades to its comments."""
        u = User(email="postauthor@example.com", username="postauthor", password="Password123!")
        db.session.add(u)
        db.session.commit()

        p = Post(body="Post to be deleted", author=u)
        db.session.add(p)
        db.session.commit()

        c = Comment(body="Comment on post", post=p, author=u)
        db.session.add(c)
        db.session.commit()

        db.session.delete(p)
        db.session.commit()

        self.assertIsNone(db.session.get(Post, p.id))
        self.assertIsNone(db.session.get(Comment, c.id))
