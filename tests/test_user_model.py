import base64
import json
import unittest

import sqlalchemy as sa
from itsdangerous import TimestampSigner

from app import create_app, db
from app.models import (
    RESET_PASSWORD_TOKEN_SALT,
    AnonymousUser,
    Comment,
    Follow,
    Permission,
    Post,
    PostLike,
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

    def test_user_instantiation_has_no_transaction_side_effects(self):
        """BLOGG-SEC-010: Ensure constructing a User does not commit or persist to database."""
        # 1. Merely instantiating User must not attach to session or write to DB
        u = User(email="transient@example.com", username="transient", password="Password123!")
        self.assertNotIn(u, db.session)
        self.assertNotIn(u, db.session.new)

        # Rollback session to prove no implicit transaction was started/committed
        db.session.rollback()
        self.assertIsNone(User.query.filter_by(username="transient").first())

        # 2. Explicitly adding and committing persists and establishes auto self-follow
        db.session.add(u)
        db.session.commit()
        self.assertIsNotNone(User.query.filter_by(username="transient").first())
        self.assertTrue(u.is_following(u))
        self.assertEqual(u.followers.count(), 1)
        self.assertEqual(u.followed.count(), 1)

    def test_follow_unfollow_transaction_control(self):
        """BLOGG-SEC-010: Ensure follow and unfollow methods do not prematurely commit caller transactions."""
        u1 = User(email="u1@example.com", username="u1", password="Password123!")
        u2 = User(email="u2@example.com", username="u2", password="Password123!")
        db.session.add_all([u1, u2])
        db.session.commit()

        # Follow without commit should be rollable-back
        u1.follow(u2)
        u1.location = "Uncommitted Location"
        # Rollback should revert both follow and location
        db.session.rollback()
        db.session.refresh(u1)
        self.assertIsNone(u1.location)
        self.assertFalse(u1.is_following(u2))

        # Follow with explicit caller commit
        u1.follow(u2)
        db.session.commit()
        self.assertTrue(u1.is_following(u2))

        # Unfollow without commit should be rollable-back
        u1.unfollow(u2)
        db.session.rollback()
        self.assertTrue(u1.is_following(u2))

        # Unfollow with explicit caller commit
        u1.unfollow(u2)
        db.session.commit()
        self.assertFalse(u1.is_following(u2))

    def test_sqlite_foreign_key_enforcement_and_sql_cascades(self):
        """BLOGG-SEC-012: Ensure SQLite PRAGMA foreign_keys is active and cascades delete dependent records."""
        # 1. Verify PRAGMA foreign_keys is enabled
        with db.engine.connect() as conn:
            val = conn.exec_driver_sql("PRAGMA foreign_keys").scalar()
            self.assertEqual(val, 1)

        # 2. Setup user with post, comment, like, follow
        u1 = User(email="cascade1@example.com", username="cascade1", password="Password123!")
        u2 = User(email="cascade2@example.com", username="cascade2", password="Password123!")
        db.session.add_all([u1, u2])
        db.session.commit()

        u1.follow(u2)
        p1 = Post(body="Post by cascade1", author=u1)
        p2 = Post(body="Post by cascade2", author=u2)
        db.session.add_all([p1, p2])
        db.session.commit()

        c1 = Comment(body="Comment on p1 by u2", post=p1, author=u2)
        c2 = Comment(body="Comment on p2 by u1", post=p2, author=u1)
        db.session.add_all([c1, c2])
        db.session.commit()

        u1.like_post(p2)
        u2.like_post(p1)
        db.session.commit()

        u1_id, p1_id, c1_id = u1.id, p1.id, c1.id
        u2_id, p2_id, c2_id = u2.id, p2.id, c2.id

        # 3. Direct SQL deletion of u1 - must cascade to u1's posts, comments, likes, and follows
        # while preserving u2 and u2's post
        with db.engine.connect() as conn:
            conn.execute(sa.text(f"DELETE FROM users WHERE id = {u1_id}"))
            conn.commit()

        db.session.expire_all()

        # u1 and u1's post p1 are deleted
        self.assertIsNone(db.session.get(User, u1_id))
        self.assertIsNone(db.session.get(Post, p1_id))
        # c1 (comment on p1) is deleted by post cascade
        self.assertIsNone(db.session.get(Comment, c1_id))
        # c2 (comment by u1 on p2) is deleted by author cascade
        self.assertIsNone(db.session.get(Comment, c2_id))
        # Follow relationship is deleted
        self.assertIsNone(Follow.query.filter_by(follower_id=u1_id, followed_id=u2_id).first())
        # Like on p1 is deleted
        self.assertIsNone(PostLike.query.filter_by(post_id=p1_id, user_id=u2_id).first())

        # Unrelated user u2 and post p2 remain intact
        self.assertIsNotNone(db.session.get(User, u2_id))
        self.assertIsNotNone(db.session.get(Post, p2_id))
